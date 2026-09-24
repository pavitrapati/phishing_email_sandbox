"""Phishing attachment sandbox -- HTTP API.

The backend's whole interaction with this service is:
    POST /v1/analyze        -> job_id            (returns immediately)
    GET  /v1/report/{id}    -> report            (poll until status is terminal)
or, for simple callers:
    POST /v1/analyze/sync   -> report            (one blocking call)
"""
from __future__ import annotations

import asyncio
import json
import logging
import os
import time
import uuid
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone

from fastapi import BackgroundTasks, Depends, FastAPI, File, Header, HTTPException, UploadFile
from fastapi.responses import JSONResponse

from . import orchestrator, report as report_builder
from .config import settings
from .models import JobCreated, Report

logging.basicConfig(
    level=settings.LOG_LEVEL,
    format="%(asctime)s %(levelname)s [%(name)s] %(message)s",
)
log = logging.getLogger("sandbox.api")

app = FastAPI(
    title="Phishing Attachment Sandbox",
    version="1.0.0",
    description="Detonates email attachments in an isolated container and returns "
                "structured behavioural evidence for LLM-assisted phishing triage.",
)

# Detonation is blocking and Docker-bound, so it runs on a bounded thread pool rather
# than the event loop. The bound is the real concurrency limit for the whole service.
_executor = ThreadPoolExecutor(max_workers=settings.MAX_CONCURRENT_JOBS,
                               thread_name_prefix="detonate")
_jobs: dict[str, dict] = {}
_jobs_lock = asyncio.Lock()


def require_api_key(x_api_key: str | None = Header(default=None)) -> None:
    """No-op when API_KEY is unset, so local development needs no ceremony."""
    if settings.API_KEY and x_api_key != settings.API_KEY:
        raise HTTPException(status_code=401, detail="invalid or missing X-API-Key")


@app.on_event("startup")
async def on_startup() -> None:
    os.makedirs(settings.jobs_dir, exist_ok=True)
    net_dir = os.path.dirname(settings.net_log)
    os.makedirs(net_dir, exist_ok=True)
    # fakenet runs with every capability dropped (no CAP_DAC_OVERRIDE), so it is subject to
    # the plain permission bits on this shared, bind-mounted directory. The API container
    # keeps DAC_OVERRIDE, so it is the right place to make the log writable for fakenet.
    try:
        os.chmod(net_dir, 0o777)
        if not os.path.exists(settings.net_log):
            with open(settings.net_log, "a"):
                pass
        os.chmod(settings.net_log, 0o666)
    except OSError as exc:
        log.warning("could not prepare the fakenet log dir: %s", exc)
    # A crashed API can leave workers running; they hold CPU and a job directory.
    reaped = orchestrator.reap_orphans()
    if reaped:
        log.warning("removed %d orphaned worker container(s) from a previous run", reaped)
    removed = orchestrator.cleanup_old_jobs()
    if removed:
        log.info("pruned %d expired job director(ies)", removed)
    log.info("sandbox api ready (wine=%s, timeout=%ss, concurrency=%s)",
             settings.ENABLE_WINE, settings.JOB_TIMEOUT, settings.MAX_CONCURRENT_JOBS)


def _run_job(job_id: str, filename: str) -> dict:
    """The blocking half of a job. Runs on the executor, never on the event loop."""
    created = _jobs[job_id]["created_at"]
    started = time.monotonic()
    _jobs[job_id]["status"] = "running"

    meta = orchestrator.run_worker(job_id, declared_name=filename)
    observations = orchestrator.read_observations(job_id)

    if meta.get("error"):
        status = "failed"
    elif meta.get("timed_out"):
        # A timeout is not a failure: the worker writes incrementally, so partial
        # evidence is usually still on disk and is worth reporting.
        status = "timeout"
    elif observations is None:
        status = "failed"
    else:
        status = observations.get("status", "completed")

    network = orchestrator.collect_network(
        meta.get("worker_ip"), meta.get("started_at", ""), meta.get("finished_at", ""))

    finished = datetime.now(timezone.utc).isoformat()
    result = report_builder.build(
        job_id=job_id,
        status=status,
        created_at=created,
        finished_at=finished,
        duration=round(time.monotonic() - started, 2),
        observations=observations,
        network=network,
        engine_meta={k: v for k, v in meta.items() if k != "logs"},
    )
    if meta.get("error"):
        result["errors"].append({"stage": "orchestrator", "error": meta["error"]})
        result["llm_summary"] = report_builder.build_llm_summary(result)

    # Persist next to the sample so a report survives an API restart.
    try:
        out = os.path.join(settings.jobs_dir, job_id, "output", "report.json")
        with open(out, "w", encoding="utf-8") as fh:
            json.dump(result, fh, indent=2, default=str)
    except OSError as exc:
        log.warning("job %s: could not persist report: %s", job_id, exc)

    _jobs[job_id].update({"status": status, "report": result})
    log.info("job %s finished: %s, verdict=%s score=%s", job_id, status,
             result["verdict"]["level"], result["verdict"]["score"])
    return result


async def _read_upload(upload: UploadFile) -> bytes:
    """Read the upload with a hard cap, so a huge file cannot exhaust memory."""
    chunks: list[bytes] = []
    total = 0
    while chunk := await upload.read(1024 * 1024):
        total += len(chunk)
        if total > settings.MAX_UPLOAD_BYTES:
            raise HTTPException(
                status_code=413,
                detail=f"file exceeds MAX_UPLOAD_BYTES ({settings.MAX_UPLOAD_BYTES} bytes)",
            )
        chunks.append(chunk)
    if total == 0:
        raise HTTPException(status_code=400, detail="uploaded file is empty")
    return b"".join(chunks)


@app.get("/healthz")
async def healthz() -> dict:
    try:
        orchestrator.client().ping()
        docker_ok = True
    except Exception as exc:  # pragma: no cover - depends on the daemon
        docker_ok = False
        log.warning("docker ping failed: %s", exc)
    return {
        "status": "ok" if docker_ok else "degraded",
        "docker": docker_ok,
        "wine_enabled": settings.ENABLE_WINE,
        "active_jobs": sum(1 for j in _jobs.values() if j["status"] in ("queued", "running")),
    }


@app.post("/v1/analyze", response_model=JobCreated, status_code=202,
          dependencies=[Depends(require_api_key)])
async def analyze(background: BackgroundTasks, file: UploadFile = File(...)) -> JobCreated:
    """Submit an attachment. Returns immediately with a job id to poll."""
    content = await _read_upload(file)
    job_id = uuid.uuid4().hex
    filename = file.filename or "sample.bin"

    orchestrator.prepare_job_dir(job_id, filename, content)
    async with _jobs_lock:
        _jobs[job_id] = {
            "status": "queued",
            "created_at": datetime.now(timezone.utc).isoformat(),
            "filename": filename,
            "report": None,
        }

    loop = asyncio.get_running_loop()
    loop.run_in_executor(_executor, _run_job, job_id, filename)

    log.info("job %s queued for %r (%d bytes)", job_id, filename, len(content))
    return JobCreated(job_id=job_id, status="queued", poll=f"/v1/report/{job_id}")


@app.post("/v1/analyze/sync", dependencies=[Depends(require_api_key)])
async def analyze_sync(file: UploadFile = File(...)) -> JSONResponse:
    """Submit and wait. Convenient for a backend that has nowhere to put a poll loop."""
    content = await _read_upload(file)
    job_id = uuid.uuid4().hex
    filename = file.filename or "sample.bin"

    orchestrator.prepare_job_dir(job_id, filename, content)
    _jobs[job_id] = {
        "status": "queued",
        "created_at": datetime.now(timezone.utc).isoformat(),
        "filename": filename,
        "report": None,
    }

    loop = asyncio.get_running_loop()
    try:
        result = await asyncio.wait_for(
            loop.run_in_executor(_executor, _run_job, job_id, filename),
            timeout=settings.JOB_TIMEOUT + 60,
        )
    except asyncio.TimeoutError:
        raise HTTPException(
            status_code=504,
            detail=f"analysis exceeded the synchronous budget; poll /v1/report/{job_id}",
        )
    return JSONResponse(content=result)


@app.get("/v1/report/{job_id}", dependencies=[Depends(require_api_key)])
async def get_report(job_id: str) -> JSONResponse:
    job = _jobs.get(job_id)

    if job is None:
        # Fall back to disk so reports survive an API restart.
        path = os.path.join(settings.jobs_dir, job_id, "output", "report.json")
        if os.path.isfile(path):
            with open(path, "r", encoding="utf-8") as fh:
                return JSONResponse(content=json.load(fh))
        raise HTTPException(status_code=404, detail="unknown job id")

    if job["report"] is None:
        return JSONResponse(
            status_code=202,
            content={"job_id": job_id, "status": job["status"],
                     "created_at": job["created_at"]},
        )
    return JSONResponse(content=job["report"])


@app.get("/v1/jobs", dependencies=[Depends(require_api_key)])
async def list_jobs(limit: int = 50) -> dict:
    items = [
        {
            "job_id": job_id,
            "status": job["status"],
            "filename": job["filename"],
            "created_at": job["created_at"],
            "verdict": (job["report"] or {}).get("verdict"),
        }
        for job_id, job in list(_jobs.items())[-limit:]
    ]
    return {"count": len(items), "jobs": list(reversed(items))}


@app.delete("/v1/jobs/{job_id}", dependencies=[Depends(require_api_key)])
async def delete_job(job_id: str) -> dict:
    import shutil
    _jobs.pop(job_id, None)
    path = os.path.join(settings.jobs_dir, job_id)
    if os.path.isdir(path):
        shutil.rmtree(path, ignore_errors=True)
        return {"deleted": job_id}
    raise HTTPException(status_code=404, detail="unknown job id")


@app.get("/v1/signatures", dependencies=[Depends(require_api_key)])
async def list_signatures() -> dict:
    """The full rule set, so the backend can explain a verdict without guessing."""
    from . import signatures
    return {
        "count": len(signatures._RULES),
        "signatures": [
            {"id": sid, "name": name, "severity": sev, "description": desc}
            for sid, name, sev, desc, _ in
            sorted(signatures._RULES, key=lambda r: -r[2])
        ],
    }
