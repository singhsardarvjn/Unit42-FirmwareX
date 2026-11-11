import io
import zipfile

import pytest
from fastapi.testclient import TestClient

from app.config import Settings
from app.main import create_app
from app.samples import build_sample_firmware_zip


def upload(client, blob=None, name="fw.zip", authorized="true"):
    blob = build_sample_firmware_zip() if blob is None else blob
    return client.post("/api/v1/firmware/upload", files={"file": (name, blob)}, data={"authorized": authorized})


def test_health_and_dashboard(client):
    h = client.get("/api/v1/health").json()
    assert h["status"] == "ok" and h["binary_execution"] is False
    page = client.get("/")
    assert page.status_code == 200 and "Unit42-FirmwareX" in page.text


def test_upload_requires_authorization(client):
    r = upload(client, authorized="false")
    assert r.status_code == 400 and "licensed" in r.json()["detail"]
    assert client.post("/api/v1/firmware/upload", files={"file": ("a.bin", b"x")}).status_code == 400


def test_upload_empty_file_rejected(client):
    assert upload(client, b"").status_code == 400


def test_upload_too_large_rejected(settings):
    settings.max_upload_bytes = 1000
    c = TestClient(create_app(settings))
    r = upload(c, b"x" * 5000)
    assert r.status_code == 413
    assert list(settings.upload_dir.glob("*")) == []


def test_full_flow_all_prd_endpoints(client):
    r = upload(client)
    assert r.status_code == 202
    fid, job_id = r.json()["firmware_id"], r.json()["job_id"]

    st = client.get(f"/api/v1/firmware/{fid}").json()
    assert st["status"] == "complete" and st["summary"]["binaries"] == 5

    fs = client.get(f"/api/v1/firmware/{fid}/filesystem").json()["files"]
    assert {"/bin/httpd", "/etc/shadow"} <= {f["path"] for f in fs}
    assert all(len(f["sha256"]) == 64 for f in fs)

    audit = client.get(f"/api/v1/firmware/{fid}/binary-audit").json()
    httpd = next(b for b in audit["binaries"] if b["path"] == "/bin/httpd")
    assert httpd["architecture"] == "MIPS" and httpd["endianness"] == "big" and httpd["bits"] == 32
    assert httpd["nx"] is True and httpd["pie"] is False and httpd["relro"] == "none"
    assert httpd["stack_canary"] is False and httpd["fortify"] is False and httpd["stripped"] is True

    v = client.get(f"/api/v1/firmware/{fid}/vulnerabilities").json()
    assert v["count"] == len(v["findings"]) > 0

    rep = client.get(f"/api/v1/firmware/{fid}/report")
    assert rep.status_code == 200 and rep.json()["firmware_id"] == fid
    assert "attachment" in client.get(f"/api/v1/firmware/{fid}/report?download=true").headers["content-disposition"]

    j = client.get(f"/api/v1/jobs/{job_id}").json()
    assert j["status"] == "complete" and any(s["name"] == "unpack" for s in j["telemetry"])
    assert client.get("/api/v1/firmware").json()["firmware"][0]["firmware_id"] == fid


def test_upload_file_is_deleted_after_analysis(client, settings):
    upload(client)
    assert list(settings.upload_dir.glob("*")) == [] and list(settings.work_dir.glob("*")) == []


def test_vulnerability_filters(client):
    fid = upload(client).json()["firmware_id"]
    crit = client.get(f"/api/v1/firmware/{fid}/vulnerabilities", params={"risk": "critical"}).json()
    assert crit["count"] == 1 and crit["findings"][0]["cwe"] == "CWE-321"
    cmd = client.get(f"/api/v1/firmware/{fid}/vulnerabilities", params={"category": "command_injection"}).json()
    assert cmd["count"] > 0 and {f["cwe"] for f in cmd["findings"]} == {"CWE-78"}
    assert client.get(f"/api/v1/firmware/{fid}/vulnerabilities", params={"cwe": "CWE-798"}).json()["count"] >= 2
    assert client.get(f"/api/v1/firmware/{fid}/vulnerabilities", params={"risk": "bogus"}).status_code == 422


def test_triage_status_update_and_audit(client):
    fid = upload(client).json()["firmware_id"]
    vid = client.get(f"/api/v1/firmware/{fid}/vulnerabilities").json()["findings"][0]["vulnerability_id"]
    r = client.patch(f"/api/v1/firmware/{fid}/vulnerabilities/{vid}", json={"status": "validated"})
    assert r.status_code == 200 and r.json()["status"] == "validated"
    stored = client.get(f"/api/v1/firmware/{fid}/vulnerabilities").json()["findings"]
    assert next(f for f in stored if f["vulnerability_id"] == vid)["status"] == "validated"
    assert client.patch(f"/api/v1/firmware/{fid}/vulnerabilities/{vid}", json={"status": "nope"}).status_code == 422
    assert client.patch(f"/api/v1/firmware/{fid}/vulnerabilities/missing", json={"status": "new"}).status_code == 404
    actions = [e["action"] for e in client.get(f"/api/v1/firmware/{fid}/audit").json()["events"]]
    assert {"firmware_uploaded", "analysis_started", "analysis_completed", "finding_triaged"} <= set(actions)


def test_audit_chain_verifies(client):
    upload(client)
    client.post("/api/v1/samples")
    v = client.get("/api/v1/audit/verify").json()
    assert v["valid"] is True and v["entries"] >= 6


def test_sample_endpoint(client):
    r = client.post("/api/v1/samples")
    assert r.status_code == 202 and r.json()["synthetic"] is True
    fid = r.json()["firmware_id"]
    assert client.get(f"/api/v1/firmware/{fid}").json()["is_sample"] is True
    assert client.get(f"/api/v1/firmware/{fid}/report").json()["summary"]["findings"] > 0


def test_not_found_and_not_ready(client, settings):
    for path in ("", "/filesystem", "/binary-audit", "/vulnerabilities", "/report", "/audit"):
        assert client.get(f"/api/v1/firmware/nope{path}").status_code == 404
    assert client.get("/api/v1/jobs/nope").status_code == 404
    store = client.app.state.store
    store.create_job("pending-1", "x.bin", 1, "h")
    r = client.get("/api/v1/firmware/pending-1/filesystem")
    assert r.status_code == 409 and "not complete" in r.json()["detail"]


def test_failed_analysis_is_reported_without_leaking_details(settings, monkeypatch):
    import app.main as main

    def boom(*a, **k):
        raise RuntimeError("secret internal path /root/x")

    monkeypatch.setattr(main, "analyze_firmware", boom)
    c = TestClient(main.create_app(settings))
    fid = upload(c).json()["firmware_id"]
    j = c.get(f"/api/v1/firmware/{fid}").json()
    assert j["status"] == "failed" and "RuntimeError" in j["error"] and "/root/x" not in j["error"]
    assert c.get(f"/api/v1/firmware/{fid}/report").status_code == 409
    assert list(settings.upload_dir.glob("*")) == []


def test_queue_backpressure(settings):
    settings.max_pending_jobs = 1
    c = TestClient(create_app(settings))
    c.app.state.store.create_job("busy", "x", 1, "h")
    assert upload(c).status_code == 429
    assert c.post("/api/v1/samples").status_code == 429


def test_restart_marks_interrupted_jobs_failed(settings):
    c = TestClient(create_app(settings))
    c.app.state.store.create_job("stuck", "x", 1, "h")
    c2 = TestClient(create_app(settings))
    j = c2.get("/api/v1/firmware/stuck").json()
    assert j["status"] == "failed" and "restart" in j["error"]


def test_malicious_zip_via_api_is_contained(client, tmp_path):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        z.writestr("../../pwned.txt", "x")
        z.writestr("etc/ok.cfg", "a=b")
    fid = upload(client, buf.getvalue()).json()["firmware_id"]
    assert client.get(f"/api/v1/firmware/{fid}").json()["summary"]["skipped_entries"] == 1
    assert not (tmp_path / "pwned.txt").exists()


def test_threaded_mode_completes(tmp_path):
    import time
    s = Settings(data_dir=tmp_path / "d")  # inline=False -> background worker
    c = TestClient(create_app(s))
    fid = c.post("/api/v1/samples").json()["firmware_id"]
    for _ in range(100):
        if c.get(f"/api/v1/firmware/{fid}").json()["status"] in ("complete", "failed"):
            break
        time.sleep(0.1)
    assert c.get(f"/api/v1/firmware/{fid}").json()["status"] == "complete"


def test_dashboard_wires_download_buttons(client):
    html = client.get("/").text
    assert '$("#dl").onclick' in html and "report?download=true" in html
    assert '$("#csv").onclick' in html and "#fa582d" not in html  # brown theme, no old orange
