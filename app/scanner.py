"""Secret and weak-crypto scanning with redaction.

Raw secret values are NEVER returned: only a keyed HMAC-SHA256 fingerprint (PRD SC-3.1/3.2)."""
from __future__ import annotations

import hashlib
import hmac
import re

from .findings import make_finding

PLACEHOLDERS = {
    b"changeme", b"change_me", b"example", b"your_api_key", b"your_secret", b"password",
    b"placeholder", b"null", b"none", b"empty", b"xxxxxxxx", b"********", b"<password>",
}

KV_RE = re.compile(
    rb"(?i)(?<![A-Za-z0-9])([A-Za-z0-9_.-]{0,32}?(?:passwd|password|pwd|secret|api[_-]?key|access[_-]?token|auth[_-]?token))"
    rb"[\"']?[ \t]*[:=][ \t]*[\"']?([A-Za-z0-9_@#$%^&*+=./!?:-]{4,128})"
)
PEM_RE = re.compile(rb"-----BEGIN (?:RSA |EC |DSA |OPENSSH |ENCRYPTED )?PRIVATE KEY-----.{0,8192}?(?:-----END [A-Z ]*PRIVATE KEY-----|\Z)", re.S)
AWS_RE = re.compile(rb"(?<![A-Z0-9])AKIA[0-9A-Z]{16}(?![A-Z0-9])")
SHADOW_RE = re.compile(rb"(?m)^([a-z_][a-z0-9_-]{0,31}):(\$(?:1|5|6|y|2[aby])\$[^:\s]{4,}):")
WEAK_CFG_RE = re.compile(rb"(?i)\b(hash|digest|cipher|algo\w*|crypt\w*|encrypt\w*)[\w-]*[ \t]*[:=][ \t]*[\"']?(md5|md4|sha-?1|rc4|3?des)\b")

WEAK_IMPORTS = {
    "MD5": ("CWE-328", "MD5"), "MD5_Init": ("CWE-328", "MD5"), "EVP_md5": ("CWE-328", "MD5"),
    "SHA1": ("CWE-328", "SHA-1"), "SHA1_Init": ("CWE-328", "SHA-1"), "EVP_sha1": ("CWE-328", "SHA-1"),
    "RC4": ("CWE-327", "RC4"), "RC4_set_key": ("CWE-327", "RC4"), "EVP_rc4": ("CWE-327", "RC4"),
    "DES_ecb_encrypt": ("CWE-327", "DES"), "DES_set_key": ("CWE-327", "DES"), "DES_crypt": ("CWE-327", "DES"),
    "EVP_des_cbc": ("CWE-327", "DES"), "EVP_des_ede3_cbc": ("CWE-327", "3DES"),
}


def fingerprint(key: bytes, value: bytes) -> str:
    return hmac.new(key, value, hashlib.sha256).hexdigest()[:24]


def _plausible(value: bytes) -> bool:
    low = value.lower()
    if low in PLACEHOLDERS or len(set(value)) < 3:
        return False
    return not (b"%" in value or b"$(" in value or value.startswith((b"{", b"<", b"$")) or b"${" in value)


def scan_secrets(data: bytes, path: str, firmware_id: str, key: bytes, architecture: str | None = None, limit: int = 10) -> list[dict]:
    out: list[dict] = []

    def add(label: str, cwe: str, risk: str, conf: str, value: bytes, offset: int, title: str) -> None:
        if len(out) >= limit:
            return
        fp = fingerprint(key, value)
        out.append(make_finding(
            firmware_id, path, "hardcoded_secret", cwe, risk, conf, title,
            f"A {label} was found in this file. The value is not stored or displayed; only a keyed fingerprint is retained "
            "so the same secret can be recognised elsewhere. Validate manually.",
            f"hmac-sha256:{fp}", architecture=architecture, redacted=True, location={"file_offset": offset},
        ))

    for m in PEM_RE.finditer(data):
        add("private key block", "CWE-321", "critical", "confirmed", m.group(0)[:2048], m.start(), "Embedded private key")
    for m in AWS_RE.finditer(data):
        add("cloud access key identifier", "CWE-798", "high", "probable", m.group(0), m.start(), "Hardcoded access key ID")
    for m in SHADOW_RE.finditer(data):
        user = m.group(1).decode("ascii", "ignore")
        add("password hash", "CWE-798", "high" if user == "root" else "medium", "probable", m.group(2), m.start(),
            f"Password hash for account '{user}'")
    for m in KV_RE.finditer(data):
        value = m.group(2)
        if not _plausible(value):
            continue
        name = m.group(1).decode("ascii", "ignore").lower()
        is_pw = any(k in name for k in ("pass", "pwd"))
        add("credential-like value", "CWE-259" if is_pw else "CWE-798", "high", "probable", value, m.start(),
            f"Hardcoded {'password' if is_pw else 'secret / API key'} ({name[:40]})")
    return out


def scan_weak_crypto(data: bytes, imports: list[str] | None, path: str, firmware_id: str, architecture: str | None = None) -> list[dict]:
    out: list[dict] = []
    seen: set[str] = set()
    for name in imports or []:
        hit = WEAK_IMPORTS.get(name)
        if hit and hit[1] not in seen:
            seen.add(hit[1])
            cwe, algo = hit
            out.append(make_finding(
                firmware_id, path, "weak_crypto", cwe, "medium", "probable", f"Imports weak primitive: {algo}",
                f"The binary imports '{name}'. {algo} is deprecated for security use. Imports show linkage, not how it is used.",
                f"import:{name}", architecture=architecture, sink=name))
    if imports is None:  # text / config file
        for m in WEAK_CFG_RE.finditer(data):
            algo = m.group(2).decode().upper()
            cwe = "CWE-328" if algo in ("MD5", "MD4", "SHA1", "SHA-1") else "CWE-327"
            if algo not in seen:
                seen.add(algo)
                out.append(make_finding(
                    firmware_id, path, "weak_crypto", cwe, "medium", "heuristic", f"Config selects weak algorithm: {algo}",
                    f"A configuration line selects {algo}. Confirm whether it protects anything security-relevant.",
                    f"config:{algo.lower()}", location={"file_offset": m.start()}))
    return out
