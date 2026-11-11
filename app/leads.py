"""Static source->sink *leads* from imported symbols. This is triage, not taint proof."""
from __future__ import annotations

from .findings import bump, make_finding
from .elf_audit import hardening_score  # noqa: F401  (re-exported for convenience)

SINKS = {
    "gets": ("memory_corruption", "CWE-120", "high"),
    "strcpy": ("memory_corruption", "CWE-120", "medium"),
    "strcat": ("memory_corruption", "CWE-120", "medium"),
    "sprintf": ("memory_corruption", "CWE-120", "medium"),
    "vsprintf": ("memory_corruption", "CWE-120", "medium"),
    "sscanf": ("memory_corruption", "CWE-120", "low"),
    "memcpy": ("memory_corruption", "CWE-787", "low"),
    "system": ("command_injection", "CWE-78", "high"),
    "popen": ("command_injection", "CWE-78", "high"),
    "execve": ("command_injection", "CWE-78", "medium"),
    "execl": ("command_injection", "CWE-78", "medium"),
    "execv": ("command_injection", "CWE-78", "medium"),
    "execvp": ("command_injection", "CWE-78", "medium"),
}
SOURCES = {
    "getenv", "recv", "recvfrom", "recvmsg", "websGetVar", "nvram_get", "nvram_safe_get",
    "cgiGetValue", "httpGetEnv", "get_cgi", "web_get", "getparam",
}


def sink_leads(firmware_id: str, path: str, binary: dict) -> list[dict]:
    imports = set(binary.get("imports", []))
    sources = sorted(imports & SOURCES)
    out = []
    for sink in sorted(imports & SINKS.keys()):
        category, cwe, risk = SINKS[sink]
        if sources:
            risk, conf = bump(risk), "probable"
            note = (f" The same binary also imports input sources ({', '.join(sources[:3])}), so attacker-controlled data "
                    "may reach it. Data flow is NOT proven.")
        else:
            conf, note = "heuristic", " No known input-source import was seen in this binary."
        out.append(make_finding(
            firmware_id, path, category, cwe, risk, conf, f"Risky function imported: {sink}()",
            f"'{sink}' is linked into this binary and is commonly involved in {category.replace('_', ' ')} bugs.{note} "
            "Validate in a disassembler before reporting.",
            f"import:{sink}", architecture=binary["architecture"], sink=sink,
            source=f"import:{sources[0]}" if sources else None))
    return out


def mitigation_findings(firmware_id: str, path: str, b: dict) -> list[dict]:
    missing = []
    if b["nx"] is False:
        missing.append("NX (executable stack)")
    if not b["is_library"] and not b["pie"]:
        missing.append("PIE/ASLR")
    if b["relro"] == "none":
        missing.append("RELRO")
    if not b["stack_canary"]:
        missing.append("stack canary")
    out = []
    if missing:
        risk = "medium" if b["nx"] is False else "low"
        out.append(make_finding(
            firmware_id, path, "missing_mitigation", "CWE-693", risk, "probable",
            f"Missing exploit mitigations: {', '.join(missing)}",
            "Header/symbol inspection indicates these hardening features are absent. They make memory-corruption bugs "
            "easier to exploit; they are not vulnerabilities by themselves. Compare with checksec on spot checks.",
            "mitigation:" + ",".join(m.split()[0].lower() for m in missing), architecture=b["architecture"]))
    if b.get("writable_executable_segment"):
        out.append(make_finding(
            firmware_id, path, "missing_mitigation", "CWE-693", "medium", "confirmed", "Writable and executable memory segment",
            "A PT_LOAD segment is mapped both writable and executable (W^X violated).",
            "segment:rwx", architecture=b["architecture"]))
    return out
