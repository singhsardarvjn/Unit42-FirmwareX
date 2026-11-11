import io
import json
import zipfile

from app.analyzer import analyze_firmware
from app.config import Settings
from app.samples import build_elf, build_sample_firmware_zip, sample_files

KEY = b"k" * 32


def run(tmp_path, blob, name="t.zip", **overrides):
    s = Settings(data_dir=tmp_path / "d", **overrides)
    s.ensure_dirs()
    p = tmp_path / name
    p.write_bytes(blob)
    return analyze_firmware(p, name, "fw-1", s, KEY), s


def test_sample_firmware_end_to_end(tmp_path):
    r, s = run(tmp_path, build_sample_firmware_zip())
    sm = r["summary"]
    assert sm["files"] == len(sample_files()) and sm["binaries"] == 5 and sm["incomplete"] is False
    assert r["format"]["container"] == "ZIP archive" and r["schema_version"] == "1.0"
    assert sm["findings_by_risk"]["critical"] == 1
    assert set(sm["findings_by_category"]) == {"hardcoded_secret", "memory_corruption", "command_injection", "weak_crypto", "missing_mitigation"}
    assert sm["architectures"] == {"MIPS": 1, "ARM32": 2, "ARM64": 2}
    httpd = next(b for b in r["binaries"] if b["path"] == "/bin/httpd")
    assert httpd["architecture"] == "MIPS" and httpd["nx"] is True and httpd["pie"] is False and httpd["relro"] == "none"
    sshd = next(b for b in r["binaries"] if b["path"] == "/sbin/sshd")
    assert sshd["hardening_score"] == 5
    assert not list(s.work_dir.glob("*")), "extracted files must be deleted after analysis"


def test_report_matches_appendix_a_schema(tmp_path):
    r, _ = run(tmp_path, build_sample_firmware_zip())
    required = {"vulnerability_id", "firmware_id", "binary", "architecture", "category", "cwe", "address", "sink", "source",
                "tainted_path", "crash_state", "risk_rating", "confidence", "evidence_ref", "redacted", "status", "detected_at"}
    for f in r["findings"]:
        assert required <= set(f)
        assert f["risk_rating"] in {"critical", "high", "medium", "low", "info"}
        assert f["confidence"] in {"confirmed", "probable", "heuristic"}
        assert f["category"] in {"memory_corruption", "hardcoded_secret", "weak_crypto", "missing_mitigation", "command_injection"}
        assert set(f["crash_state"]) == {"fault_address", "registers", "overflow_offset", "stack_hash"}


def test_raw_secrets_never_appear_in_report(tmp_path):
    r, _ = run(tmp_path, build_sample_firmware_zip())
    text = json.dumps(r)
    for secret in ("DemoPassw0rd!", "DEMO_NOT_A_REAL_KEY_123456", "AbCdEfGhIjKlMnOpQrStU", "BEGIN RSA PRIVATE KEY"):
        assert secret not in text
    assert all(f["redacted"] for f in r["findings"] if f["category"] == "hardcoded_secret")


def test_honest_about_unimplemented_stages(tmp_path):
    r, _ = run(tmp_path, build_sample_firmware_zip())
    status = {s["name"]: s["status"] for s in r["stages"]}
    assert status["emulation"] == status["symbolic_taint"] == status["fuzzing"] == "not_implemented"
    assert r["safety"]["binary_execution"] is False and r["safety"]["emulation"] is False
    assert all(f["tainted_path"] == [] and f["address"] is None for f in r["findings"])


def test_raw_elf_image_is_analysed(tmp_path):
    r, _ = run(tmp_path, build_elf("ARM32", imports=["strcpy", "recv"]), "raw.bin")
    assert r["format"]["container"] == "Raw firmware image" and r["summary"]["binaries"] == 1
    assert any(f["sink"] == "strcpy" and f["confidence"] == "probable" for f in r["findings"])


def test_traversal_entries_are_skipped_and_counted(tmp_path):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        z.writestr("ok.txt", "fine")
        z.writestr("../../escape.txt", "no")
    r, _ = run(tmp_path, buf.getvalue())
    assert r["summary"]["files"] == 1 and r["summary"]["skipped_entries"] == 1
    assert not (tmp_path / "escape.txt").exists()


def test_corrupt_elf_does_not_crash(tmp_path):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        z.writestr("bin/bad", b"\x7fELF\x02\x01\x01" + b"\xff" * 40)
        z.writestr("bin/good", build_elf("MIPS"))
    r, _ = run(tmp_path, buf.getvalue())
    assert r["summary"]["binaries"] == 1
    assert any("could not be parsed" in l for l in r["limitations"])


def test_wall_clock_quota_returns_partial_result(tmp_path):
    r, _ = run(tmp_path, build_sample_firmware_zip(), job_timeout_seconds=-1)
    assert r["summary"]["incomplete"] is True and r["summary"]["files"] == 0
    assert any("quota" in l.lower() for l in r["limitations"])


def test_extraction_limit_marks_incomplete(tmp_path):
    r, _ = run(tmp_path, build_sample_firmware_zip(), max_files=3)
    assert r["summary"]["incomplete"] is True and r["format"]["container"] == "Partially extracted"


def test_oversized_input_rejected(tmp_path):
    import pytest
    with pytest.raises(ValueError):
        run(tmp_path, b"x" * 100, max_upload_bytes=10)


def test_empty_firmware_has_no_findings(tmp_path):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        z.writestr("readme.txt", "Normal public documentation.")
    r, _ = run(tmp_path, buf.getvalue())
    assert r["summary"]["findings"] == 0 and r["binaries"] == []
