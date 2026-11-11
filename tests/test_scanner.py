import json

from app.leads import mitigation_findings, sink_leads
from app.scanner import fingerprint, scan_secrets, scan_weak_crypto

KEY = b"k" * 32


def test_password_is_detected_and_redacted():
    f = scan_secrets(b"admin_password=SuperSecret987\n", "/etc/cfg", "fw", KEY)
    assert len(f) == 1 and f[0]["cwe"] == "CWE-259" and f[0]["redacted"] is True
    assert f[0]["evidence_ref"] == "hmac-sha256:" + fingerprint(KEY, b"SuperSecret987")
    assert "SuperSecret987" not in json.dumps(f)


def test_fingerprint_depends_on_key():
    assert fingerprint(b"a" * 32, b"x") != fingerprint(b"b" * 32, b"x")


def test_api_key_cwe798_and_placeholders_ignored():
    assert scan_secrets(b'api_key = "AbCd1234EfGh5678"', "/a", "fw", KEY)[0]["cwe"] == "CWE-798"
    assert scan_secrets(b"password=changeme\npassword=%s\npwd=${PWD}\nsecret=aaaaaaaa", "/a", "fw", KEY) == []


def test_private_key_block_is_critical_and_redacted():
    pem = b"-----BEGIN RSA PRIVATE KEY-----\nQUJDREVGR0hJSktMTU5PUA==\n-----END RSA PRIVATE KEY-----\n"
    f = scan_secrets(pem, "/k.pem", "fw", KEY)
    assert f[0]["risk_rating"] == "critical" and f[0]["cwe"] == "CWE-321"
    assert "QUJDREVG" not in json.dumps(f)


def test_aws_key_and_shadow_hash():
    f = scan_secrets(b"AKIAABCDEFGHIJKLMNOP", "/a", "fw", KEY)
    assert f and f[0]["cwe"] == "CWE-798"
    s = scan_secrets(b"root:$1$salt$abcdefghijklmnop:19000:0:::", "/etc/shadow", "fw", KEY)
    assert s[0]["risk_rating"] == "high" and "root" in s[0]["title"]
    assert "abcdefghijklmnop" not in json.dumps(s)


def test_secret_limit_per_file():
    data = b"\n".join(b"password=Value%03dXYZ" % i for i in range(50))
    assert len(scan_secrets(data, "/a", "fw", KEY, limit=10)) == 10


def test_weak_crypto_imports_and_config():
    f = scan_weak_crypto(b"", ["MD5_Init", "RC4", "EVP_md5", "printf"], "/bin/x", "fw", "MIPS")
    assert sorted(x["title"] for x in f) == ["Imports weak primitive: MD5", "Imports weak primitive: RC4"]
    c = scan_weak_crypto(b"hash_algorithm=MD5\ncipher=des\n", None, "/etc/c", "fw")
    assert {x["cwe"] for x in c} == {"CWE-328", "CWE-327"}
    assert scan_weak_crypto(b"description=made by des", None, "/x", "fw") == []


BIN = {"architecture": "MIPS", "imports": ["strcpy", "memcpy", "getenv", "printf"], "nx": True, "pie": False,
       "relro": "none", "stack_canary": False, "is_library": False, "writable_executable_segment": False}


def test_sink_leads_escalate_with_source():
    f = {x["sink"]: x for x in sink_leads("fw", "/bin/x", BIN)}
    assert f["strcpy"]["risk_rating"] == "high" and f["strcpy"]["confidence"] == "probable"
    assert f["strcpy"]["source"] == "import:getenv" and f["strcpy"]["tainted_path"] == []
    assert f["memcpy"]["risk_rating"] == "medium" and f["memcpy"]["cwe"] == "CWE-787"
    alone = sink_leads("fw", "/bin/y", {**BIN, "imports": ["strcpy"]})[0]
    assert alone["risk_rating"] == "medium" and alone["confidence"] == "heuristic" and alone["source"] is None
    assert sink_leads("fw", "/bin/z", {**BIN, "imports": ["gets"]})[0]["risk_rating"] == "high"


def test_mitigation_findings():
    f = mitigation_findings("fw", "/bin/x", BIN)
    assert len(f) == 1 and f[0]["cwe"] == "CWE-693" and f[0]["risk_rating"] == "low"
    f2 = mitigation_findings("fw", "/bin/x", {**BIN, "nx": False, "writable_executable_segment": True})
    assert {x["risk_rating"] for x in f2} == {"medium"} and len(f2) == 2
    good = {**BIN, "nx": True, "pie": True, "relro": "full", "stack_canary": True}
    assert mitigation_findings("fw", "/bin/x", good) == []
