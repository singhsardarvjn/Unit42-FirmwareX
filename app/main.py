from __future__ import annotations

import hashlib
import logging
import shutil
import uuid
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from fastapi import FastAPI, File, Form, HTTPException, Query, UploadFile
from fastapi.responses import FileResponse, JSONResponse
from pydantic import BaseModel

from . import __version__
from .analyzer import analyze_firmware
from .config import Settings
from .findings import RISK_ORDER, utc_now
from .samples import build_sample_firmware_zip
from .store import Store

STATIC = Path(__file__).resolve().parent / "static"
log = logging.getLogger("firmwarex")
TRIAGE = {"new", "triaged", "validated", "false_positive"}


class TriageUpdate(BaseModel):
    status: str


def create_app(settings: Settings | None = None) -> FastAPI:
    settings = settings or Settings()
    settings.ensure_dirs()
    store = Store(settings.db_path)
    key = settings.load_fingerprint_key()
    executor = ThreadPoolExecutor(max_workers=settings.workers, thread_name_prefix="firmwarex")
    store.fail_interrupted()

    app = FastAPI(title="Unit42-FirmwareX", version=__version__,
                  description="Safe static firmware attack-surface and vulnerability analysis engine (analysis only).")
    app.state.store, app.state.settings = store, settings

    # ------------------------------------------------------------ job runner
    def run_job(firmware_id: str, path: Path, filename: str) -> None:
        def progress(stage: str, pct: int) -> None:
            store.update_job(firmware_id, stage=stage, progress=min(99, pct))

        try:
            store.update_job(firmware_id, status="running", stage="starting", progress=1, started_at=utc_now())
            store.audit(firmware_id, "analysis_started", {"filename": filename})
            report = analyze_firmware(path, filename, firmware_id, settings, key, progress)
            store.save_report(firmware_id, report)
            store.update_job(firmware_id, status="complete", stage="complete", progress=100, completed_at=utc_now())
            s = report["summary"]
            store.audit(firmware_id, "analysis_completed",
                        {"files": s["files"], "binaries": s["binaries"], "findings": s["findings"], "incomplete": s["incomplete"]})
        except Exception as exc:  # never leak internals / firmware content to the API
            log.exception("analysis failed")
            store.update_job(firmware_id, status="failed", stage="failed", progress=100,
                             error=f"Analysis failed ({type(exc).__name__}). See the server console.", completed_at=utc_now())
            store.audit(firmware_id, "analysis_failed", {"error_type": type(exc).__name__})
        finally:
            path.unlink(missing_ok=True)

    def enqueue(firmware_id: str, path: Path, filename: str) -> None:
        if settings.inline:
            run_job(firmware_id, path, filename)
        else:
            executor.submit(run_job, firmware_id, path, filename)

    def need(firmware_id: str) -> dict:
        job = store.get_job(firmware_id)
        if not job:
            raise HTTPException(404, "Firmware not found.")
        return job

    def need_report(firmware_id: str) -> dict:
        job = need(firmware_id)
        report = store.get_report(firmware_id) if job["status"] == "complete" else None
        if report is None:
            raise HTTPException(409, f"Analysis is not complete (status: {job['status']}).")
        return report

    # ------------------------------------------------------------ routes
    @app.get("/", include_in_schema=False)
    def dashboard():
        return FileResponse(STATIC / "index.html")

    @app.get("/api/v1/health")
    def health():
        return {"status": "ok", "service": "Unit42-FirmwareX", "version": __version__, "binary_execution": False,
                "network_egress_required": False, "max_upload_bytes": settings.max_upload_bytes}

    @app.post("/api/v1/firmware/upload", status_code=202)
    async def upload(file: UploadFile = File(...), authorized: bool = Form(False)):
        if not authorized:
            raise HTTPException(400, "Confirm the image is public/open-source or that you are licensed to analyse it (authorized=true).")
        if store.count_pending() >= settings.max_pending_jobs:
            raise HTTPException(429, "Analysis queue is full. Try again shortly.")
        filename = Path(file.filename or "firmware.bin").name[:200] or "firmware.bin"
        firmware_id = str(uuid.uuid4())
        dest = settings.upload_dir / f"{firmware_id}.upload"
        size, digest = 0, hashlib.sha256()
        try:
            with open(dest, "wb") as out:
                while chunk := await file.read(1024 * 1024):
                    size += len(chunk)
                    if size > settings.max_upload_bytes:
                        raise HTTPException(413, f"Upload exceeds the {settings.max_upload_bytes // (1024 * 1024)} MB limit.")
                    digest.update(chunk)
                    out.write(chunk)
            if size == 0:
                raise HTTPException(400, "The uploaded file is empty.")
        except Exception:
            dest.unlink(missing_ok=True)
            raise
        finally:
            await file.close()
        job = store.create_job(firmware_id, filename, size, digest.hexdigest())
        store.audit(firmware_id, "firmware_uploaded", {"filename": filename, "size": size, "sha256": digest.hexdigest(),
                                                       "authorization_confirmed": True})
        enqueue(firmware_id, dest, filename)
        return {"firmware_id": firmware_id, "job_id": job["job_id"], "status": "queued"}

    @app.post("/api/v1/samples", status_code=202)
    def create_sample():
        """Analyse a built-in *synthetic* demo firmware (dummy ELF headers + fake credentials)."""
        if store.count_pending() >= settings.max_pending_jobs:
            raise HTTPException(429, "Analysis queue is full. Try again shortly.")
        blob = build_sample_firmware_zip()
        firmware_id = str(uuid.uuid4())
        dest = settings.upload_dir / f"{firmware_id}.upload"
        dest.write_bytes(blob)
        sha = hashlib.sha256(blob).hexdigest()
        job = store.create_job(firmware_id, "demo-router-firmware.zip", len(blob), sha, is_sample=True)
        store.audit(firmware_id, "sample_created", {"sha256": sha, "synthetic": True})
        enqueue(firmware_id, dest, "demo-router-firmware.zip")
        return {"firmware_id": firmware_id, "job_id": job["job_id"], "status": "queued", "synthetic": True}

    @app.get("/api/v1/firmware")
    def list_firmware():
        return {"firmware": store.list_jobs()}

    @app.get("/api/v1/firmware/{firmware_id}")
    def firmware_status(firmware_id: str):
        job = need(firmware_id)
        report = store.get_report(firmware_id) if job["status"] == "complete" else None
        return {**job, "summary": report["summary"] if report else None}

    @app.get("/api/v1/firmware/{firmware_id}/filesystem")
    def filesystem(firmware_id: str):
        return {"firmware_id": firmware_id, "files": need_report(firmware_id)["inventory"],
                "note": "Virtual inventory. Extracted files are deleted after analysis."}

    @app.get("/api/v1/firmware/{firmware_id}/binary-audit")
    def binary_audit(firmware_id: str):
        return {"firmware_id": firmware_id, "binaries": need_report(firmware_id)["binaries"]}

    @app.get("/api/v1/firmware/{firmware_id}/vulnerabilities")
    def vulnerabilities(firmware_id: str, risk: str | None = Query(None), category: str | None = Query(None),
                        cwe: str | None = Query(None)):
        if risk and risk not in RISK_ORDER:
            raise HTTPException(422, f"risk must be one of {RISK_ORDER}")
        findings = need_report(firmware_id)["findings"]
        if risk:
            findings = [f for f in findings if f["risk_rating"] == risk]
        if category:
            findings = [f for f in findings if f["category"] == category]
        if cwe:
            findings = [f for f in findings if f["cwe"] == cwe]
        return {"firmware_id": firmware_id, "count": len(findings), "findings": findings}

    @app.patch("/api/v1/firmware/{firmware_id}/vulnerabilities/{vulnerability_id}")
    def triage(firmware_id: str, vulnerability_id: str, body: TriageUpdate):
        if body.status not in TRIAGE:
            raise HTTPException(422, f"status must be one of {sorted(TRIAGE)}")
        report = need_report(firmware_id)
        for f in report["findings"]:
            if f["vulnerability_id"] == vulnerability_id:
                old, f["status"] = f["status"], body.status
                store.save_report(firmware_id, report)
                store.audit(firmware_id, "finding_triaged", {"vulnerability_id": vulnerability_id, "from": old, "to": body.status})
                return f
        raise HTTPException(404, "Finding not found.")

    @app.get("/api/v1/firmware/{firmware_id}/report")
    def report(firmware_id: str, download: bool = False):
        data = need_report(firmware_id)
        headers = {"Content-Disposition": f'attachment; filename="firmwarex-{firmware_id}.json"'} if download else None
        return JSONResponse(data, headers=headers)

    @app.get("/api/v1/jobs/{job_id}")
    def job(job_id: str):
        j = store.get_job_by_job_id(job_id)
        if not j:
            raise HTTPException(404, "Job not found.")
        report = store.get_report(j["firmware_id"]) if j["status"] == "complete" else None
        return {**j, "telemetry": report["stages"] if report else []}

    @app.get("/api/v1/firmware/{firmware_id}/audit")
    def firmware_audit(firmware_id: str):
        need(firmware_id)
        return {"firmware_id": firmware_id, "events": store.audit_events(firmware_id)}

    @app.get("/api/v1/audit/verify")
    def verify_audit():
        return store.verify_audit()

    return app


app = create_app()
