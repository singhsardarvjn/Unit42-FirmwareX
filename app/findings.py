"""Finding schema (PRD Appendix A) + helpers."""
from __future__ import annotations

import uuid
from datetime import datetime, timezone

RISK_ORDER = ["critical", "high", "medium", "low", "info"]

CWE_NAMES = {
    "CWE-120": "Buffer Copy without Checking Size of Input",
    "CWE-787": "Out-of-bounds Write",
    "CWE-78": "OS Command Injection",
    "CWE-798": "Use of Hard-coded Credentials",
    "CWE-259": "Use of Hard-coded Password",
    "CWE-321": "Use of Hard-coded Cryptographic Key",
    "CWE-327": "Use of a Broken or Risky Cryptographic Algorithm",
    "CWE-328": "Use of Weak Hash",
    "CWE-693": "Protection Mechanism Failure",
}


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def bump(risk: str) -> str:
    i = RISK_ORDER.index(risk)
    return RISK_ORDER[max(1, i - 1)] if i > 1 else risk  # never auto-promote to critical


def make_finding(firmware_id: str, binary: str, category: str, cwe: str, risk: str, confidence: str,
                 title: str, description: str, evidence_ref: str, *, architecture: str | None = None,
                 sink: str | None = None, source: str | None = None, redacted: bool = False,
                 location: dict | None = None) -> dict:
    return {
        "vulnerability_id": str(uuid.uuid4()),
        "firmware_id": firmware_id,
        "binary": binary,
        "architecture": architecture,
        "category": category,
        "cwe": cwe,
        "cwe_name": CWE_NAMES.get(cwe, ""),
        "address": None,
        "sink": sink,
        "source": source,
        "tainted_path": [],
        "crash_state": {"fault_address": None, "registers": None, "overflow_offset": None, "stack_hash": None},
        "risk_rating": risk,
        "confidence": confidence,
        "evidence_ref": evidence_ref,
        "redacted": redacted,
        "status": "new",
        "detected_at": utc_now(),
        "title": title,
        "description": description,
        "location": location,
    }


def dedupe(findings: list[dict]) -> list[dict]:
    seen: dict[tuple, dict] = {}
    for f in findings:
        seen.setdefault((f["category"], f["binary"], f["cwe"], f["evidence_ref"], f["title"]), f)
    return sorted(seen.values(), key=lambda f: (RISK_ORDER.index(f["risk_rating"]), f["binary"], f["title"]))
