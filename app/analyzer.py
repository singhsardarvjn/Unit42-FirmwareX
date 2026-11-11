"""End-to-end analysis pipeline: ingest -> unpack -> inventory -> audit -> scan -> leads -> report."""
from __future__ import annotations

import hashlib
import os
import shutil
import time
from pathlib import Path
from typing import Callable

from . import __version__
from .config import Settings
from .elf_audit import ElfAuditError, audit_elf, hardening_score
from .extractor import Budget, detect_signatures, entropy_of, entropy_profile, extract_any
from .findings import RISK_ORDER, dedupe, utc_now
from .leads import mitigation_findings, sink_leads
from .scanner import scan_secrets, scan_weak_crypto

Progress = Callable[[str, int], None]

NOT_IMPLEMENTED = [
    ("emulation", "QEMU user/system-mode emulation", "Not part of this build. Needs an egress-denied Linux sandbox (Docker/KVM)."),
    ("symbolic_taint", "Symbolic execution / taint analysis (angr)", "Not part of this build. Findings above are import-based leads, not proven data flows."),
    ("fuzzing", "Protocol-aware fuzzing of emulated services", "Not part of this build (requires emulation)."),
]


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for block in iter(lambda: fh.read(1024 * 1024), b""):
            h.update(block)
    return h.hexdigest()


class _Stages:
    def __init__(self, progress: Progress | None) -> None:
        self.items: list[dict] = []
        self._progress = progress

    def run(self, name: str, label: str, pct: int, fn):
        if self._progress:
            self._progress(name, pct)
        t0 = time.perf_counter()
        item = {"name": name, "label": label, "status": "done", "detail": ""}
        try:
            result = fn()
        finally:
            item["duration_ms"] = round((time.perf_counter() - t0) * 1000)
            self.items.append(item)
        return result, item


def analyze_firmware(path: Path, filename: str, firmware_id: str, settings: Settings, key: bytes,
                     progress: Progress | None = None, workdir: Path | None = None) -> dict:
    started = time.perf_counter()
    deadline = time.monotonic() + settings.job_timeout_seconds
    stages = _Stages(progress)
    limitations: list[str] = []
    incomplete = False

    size = path.stat().st_size
    if size > settings.max_upload_bytes:
        raise ValueError("Input image exceeds the configured size limit.")

    # ---- 1. ingest
    def ingest():
        blob = path.read_bytes()
        return {"sha256": hashlib.sha256(blob).hexdigest(), "sigs": detect_signatures(blob),
                "entropy": entropy_of(blob[:262144]), "profile": entropy_profile(blob)}
    info, _ = stages.run("ingest", "Ingest, hash & signature scan", 5, ingest)

    # ---- 2. unpack
    work = (workdir or settings.work_dir / firmware_id)
    rootfs = work / "rootfs"
    if work.exists():
        shutil.rmtree(work, ignore_errors=True)
    rootfs.mkdir(parents=True, exist_ok=True)
    budget = Budget(settings.max_files, settings.max_extracted_bytes)
    try:
        container, st = stages.run("unpack", "Unpack firmware / reconstruct root filesystem", 20,
                                   lambda: extract_any(path, rootfs, budget))
        st["detail"] = container
        if budget.incomplete:
            st["status"] = "partial"
            incomplete = True

        # ---- 3. inventory + audit + scan
        inventory: list[dict] = []
        binaries: list[dict] = []
        findings: list[dict] = []
        elf_errors = 0
        files = []
        for root, dirs, names in os.walk(rootfs):
            dirs.sort()
            for n in sorted(names):
                p = Path(root, n)
                if not p.is_symlink():
                    files.append(p)

        def inspect_all():
            nonlocal incomplete, elf_errors
            for i, p in enumerate(files):
                if time.monotonic() > deadline:
                    incomplete = True
                    limitations.append("Wall-clock quota reached; remaining files were not analysed (partial result).")
                    break
                rel = "/" + p.relative_to(rootfs).as_posix()
                try:
                    fsize = p.stat().st_size
                except OSError:
                    continue
                scannable = fsize <= settings.max_scan_file_bytes
                data = b""
                if scannable:
                    try:
                        data = p.read_bytes()
                    except OSError:
                        scannable = False
                digest = hashlib.sha256(data).hexdigest() if scannable else sha256_file(p)
                binary = None
                if data[:4] == b"\x7fELF" or (not scannable and _head(p) == b"\x7fELF"):
                    if len(binaries) < settings.max_elfs:
                        try:
                            binary = audit_elf(p)
                        except ElfAuditError:
                            elf_errors += 1
                if binary:
                    rec = {"path": rel, **{k: v for k, v in binary.items() if k != "imports"},
                           "imports_count": len(binary["imports"]), "hardening_score": hardening_score(binary),
                           "risk_leads": sorted(set(binary["imports"]) & _sink_names())}
                    binaries.append(rec)
                    findings.extend(mitigation_findings(firmware_id, rel, binary))
                    findings.extend(sink_leads(firmware_id, rel, binary))
                    findings.extend(scan_weak_crypto(data, binary["imports"], rel, firmware_id, binary["architecture"]))
                elif scannable:
                    findings.extend(scan_weak_crypto(data, None, rel, firmware_id))
                if scannable and data:
                    findings.extend(scan_secrets(data, rel, firmware_id, key, binary["architecture"] if binary else None))
                inventory.append({"path": rel, "type": "file", "size": fsize, "sha256": digest,
                                  "elf": binary is not None, "content_scanned": scannable})
                if progress and i % 25 == 0:
                    progress("analyse", 30 + int(60 * (i + 1) / max(len(files), 1)))

        _, st2 = stages.run("analyse", "Binary audit, secret/crypto scan, source→sink leads", 30, inspect_all)
        st2["detail"] = f"{len(inventory)} files, {len(binaries)} ELF binaries"
        if elf_errors:
            limitations.append(f"{elf_errors} ELF file(s) could not be parsed (corrupt or truncated).")
        if any(not f["content_scanned"] for f in inventory):
            limitations.append(f"Files larger than {settings.max_scan_file_bytes // 1024 // 1024} MB were inventoried but not content-scanned.")
    finally:
        shutil.rmtree(work, ignore_errors=True)  # extracted files are never kept on disk

    # ---- 4. normalise
    def normalise():
        return dedupe(findings)
    findings, _ = stages.run("normalise", "Normalise & classify findings (CWE)", 95, normalise)

    for n, label, why in NOT_IMPLEMENTED:
        stages.items.append({"name": n, "label": label, "status": "not_implemented", "detail": why, "duration_ms": 0})

    limitations = [
        "Static analysis only: no firmware binary is ever executed or emulated.",
        "Source→sink findings are import-based leads (heuristic/probable), not proven tainted paths; addresses and crash state are null.",
        "Compressed filesystems (SquashFS) need the optional 'unsquashfs' tool; UBIFS/JFFS2/CramFS are detected by signature only.",
        "Hardening flags come from ELF headers and imported symbols; confirm with checksec on spot checks.",
    ] + budget.notes + limitations

    by_risk = {r: 0 for r in RISK_ORDER}
    by_cat: dict[str, int] = {}
    for f in findings:
        by_risk[f["risk_rating"]] += 1
        by_cat[f["category"]] = by_cat.get(f["category"], 0) + 1
    arches: dict[str, int] = {}
    for b in binaries:
        arches[b["architecture"]] = arches.get(b["architecture"], 0) + 1
    exes = [b for b in binaries if not b["is_library"]]
    hardening = {
        "executables": len(exes),
        "nx": sum(1 for b in exes if b["nx"] is True),
        "pie": sum(1 for b in exes if b["pie"]),
        "full_relro": sum(1 for b in exes if b["relro"] == "full"),
        "canary": sum(1 for b in exes if b["stack_canary"]),
        "fortify": sum(1 for b in exes if b["fortify"]),
    }

    return {
        "schema_version": "1.0",
        "engine_version": __version__,
        "firmware_id": firmware_id,
        "generated_at": utc_now(),
        "input_image": {"filename": filename, "size": size, "sha256": info["sha256"]},
        "format": {"container": container, "signatures": info["sigs"],
                   "entropy_bits_per_byte": info["entropy"], "entropy_profile": info["profile"]},
        "summary": {
            "files": len(inventory), "files_scanned": sum(1 for f in inventory if f["content_scanned"]),
            "binaries": len(binaries), "findings": len(findings), "findings_by_risk": by_risk,
            "findings_by_category": by_cat, "architectures": arches, "hardening": hardening,
            "duration_ms": round((time.perf_counter() - started) * 1000), "incomplete": incomplete,
            "skipped_entries": budget.skipped,
        },
        "stages": stages.items,
        "inventory": inventory,
        "binaries": binaries,
        "findings": findings,
        "limitations": limitations,
        "safety": {"binary_execution": False, "emulation": False, "network_egress": False,
                   "raw_secrets_persisted": False, "archive_members_extracted_as_data_only": True},
    }


def _head(p: Path) -> bytes:
    try:
        with open(p, "rb") as fh:
            return fh.read(4)
    except OSError:
        return b""


def _sink_names() -> set[str]:
    from .leads import SINKS
    return set(SINKS)
