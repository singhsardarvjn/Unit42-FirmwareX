# Unit42-FirmwareX

Safe, local **IoT firmware static-analysis platform** with a web dashboard — built from the
*Unit42-FirmwareX PRD*. Upload a firmware image and get a reconstructed file tree, an ELF
**mitigation matrix** (NX / PIE / RELRO / canary / FORTIFY), **CWE-classified findings**
(hardcoded secrets, weak crypto, risky functions, missing mitigations), a tamper-evident audit log
and a downloadable JSON report.

> **Nothing is ever executed.** Firmware is only read and inspected. Use public / open-source
> images you are licensed to analyse.

## Run it in VS Code (5 steps)

Requires **Python 3.10+**. Open the `Unit42-FirmwareX` folder in VS Code → **Terminal → New Terminal**.

**1. Create a virtual environment**

| Windows (PowerShell) | macOS / Linux |
|---|---|
| `python -m venv .venv` | `python3 -m venv .venv` |

**2. Activate it**

| Windows (PowerShell) | macOS / Linux |
|---|---|
| `.venv\Scripts\Activate.ps1` | `source .venv/bin/activate` |

*(If PowerShell blocks it: `Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass`, then activate again.)*

**3. Install dependencies**
```
pip install -r requirements.txt
```

**4. Start the app**
```
python run.py
```
Your browser opens at **http://127.0.0.1:8000** (API docs: http://127.0.0.1:8000/docs).

**5. Try it** — click **“Analyse built-in demo firmware”**, then explore the tabs:
Overview · File tree · Mitigation matrix · Findings · Pipeline & limits · Audit log.
You can also upload `samples/demo-router-firmware.zip` (tick the authorisation box first), or any
`.zip` / `.tar` / `.tar.gz` / `.cpio` / `.bin` image.

Use **Download JSON** (full report) or **Export CSV** (findings) at the top right of the report. Stop the server with `Ctrl+C`.

## Run the tests
```
python -m pytest                       # 67 tests
python -m pytest --cov=app --cov-report=term-missing
```
In VS Code you can also use the **Testing** sidebar (pytest is pre-configured) or press **F5**.

## What it does

| PRD area | Status |
|---|---|
| FR-1.1 / 1.2 Unpack & reconstruct rootfs + file inventory (path, size, SHA-256) | ✅ ZIP, TAR(.gz/.bz2/.xz), gzip, CPIO, nested archives; SquashFS if `unsquashfs` is installed; signatures for CramFS/UBI/JFFS2/ext/uImage |
| FR-1.3 / 1.4 ELF enumeration + hardening matrix | ✅ arch, endianness, bitness, NX, PIE, RELRO, canary, FORTIFY, stripped, W+X segments |
| FR-1.5 Risk leads (banned functions) | ✅ import-based source→sink leads, labelled heuristic/probable |
| Secret & crypto scanner with redaction (SC-3.x) | ✅ keys, passwords, API keys, shadow hashes, weak MD5/SHA-1/DES/RC4; **only HMAC fingerprints stored** |
| Normalised CWE findings (Appendix A schema) | ✅ |
| API §8.1 + dashboard §8.2 (tree, matrix, finding log) | ✅ (+ filters, triage status, job telemetry) |
| Immutable audit log | ✅ append-only SQLite triggers + SHA-256 hash chain, verifiable in the UI |
| Quotas (SC-2.x) | ✅ upload size, extracted bytes, file count, wall-clock, queue back-pressure |
| QEMU emulation, angr symbolic/taint, fuzzing, interactive CFG | ❌ **not in this build** – shown as “not in this build” in the UI |

### Honest limitations
* This is a **static** analyser. Source→sink findings are *leads* from imported symbols, **not** proven tainted paths; addresses and crash state are `null`.
* Hardening flags come from ELF headers/symbols – spot-check against `checksec`.
* Emulation, symbolic execution and fuzzing need an egress-denied Linux sandbox (Docker/KVM); the PRD requires a mentor sign-off for that, so they are intentionally left out.

## REST API

| Method | Endpoint | Purpose |
|---|---|---|
| POST | `/api/v1/firmware/upload` | multipart `file` + `authorized=true` → queues analysis |
| GET | `/api/v1/firmware` | list jobs |
| GET | `/api/v1/firmware/{id}` | status + summary |
| GET | `/api/v1/firmware/{id}/filesystem` | file-tree inventory |
| GET | `/api/v1/firmware/{id}/binary-audit` | mitigation matrix |
| GET | `/api/v1/firmware/{id}/vulnerabilities` | findings (`?risk=&category=&cwe=`) |
| PATCH | `/api/v1/firmware/{id}/vulnerabilities/{vid}` | triage: new / triaged / validated / false_positive |
| GET | `/api/v1/firmware/{id}/report` | full JSON (`?download=true`) |
| GET | `/api/v1/jobs/{jobId}` | job status + stage telemetry |
| GET | `/api/v1/firmware/{id}/audit` · `/api/v1/audit/verify` | audit events · verify hash chain |
| POST | `/api/v1/samples` | analyse the synthetic demo firmware |

```
curl -F "file=@samples/demo-router-firmware.zip" -F "authorized=true" http://127.0.0.1:8000/api/v1/firmware/upload
```

## Project layout
```
app/
  main.py        FastAPI app + job runner        extractor.py   safe unpacking
  analyzer.py    pipeline orchestration          elf_audit.py   ELF hardening matrix
  scanner.py     secrets / weak crypto           leads.py       source→sink + mitigation findings
  findings.py    Appendix A schema               store.py       SQLite + hash-chained audit log
  samples.py     synthetic demo firmware         static/index.html  dashboard
tests/           67 pytest tests (unit + API)    run.py         start the app
```

## Configuration (optional environment variables)
`FIRMWAREX_DATA_DIR`, `FIRMWAREX_MAX_UPLOAD` (bytes, default 100 MB), `FIRMWAREX_MAX_EXTRACTED`,
`FIRMWAREX_MAX_FILES`, `FIRMWAREX_JOB_TIMEOUT` (seconds), `FIRMWAREX_WORKERS`.

Runtime data (database, fingerprint key) lives in `data/` – delete the folder to reset.
