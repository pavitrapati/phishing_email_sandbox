"""Spawns and supervises detonation containers.

Everything about how a worker is constrained lives here, in one place, so the isolation
posture can be read and audited without hunting through the codebase.
"""
from __future__ import annotations

import json
import logging
import os
import shutil
import time
from datetime import datetime, timezone

import docker
from docker.errors import APIError, ImageNotFound, NotFound

from .config import settings

log = logging.getLogger("sandbox.orchestrator")

_client: docker.DockerClient | None = None


def client() -> docker.DockerClient:
    global _client
    if _client is None:
        _client = docker.from_env()
    return _client


def _fakenet_ip() -> str | None:
    """Find the fakenet container's address on the detonation network."""
    try:
        container = client().containers.get("sbx-fakenet")
        networks = container.attrs["NetworkSettings"]["Networks"]
        entry = networks.get(settings.DETONATION_NETWORK)
        return entry.get("IPAddress") if entry else None
    except (NotFound, APIError, KeyError):
        return None


def prepare_job_dir(job_id: str, filename: str, content: bytes) -> str:
    """Lay out the per-job directory that gets bind-mounted into the worker."""
    job_dir = os.path.join(settings.jobs_dir, job_id)
    input_dir = os.path.join(job_dir, "input")
    output_dir = os.path.join(job_dir, "output")
    os.makedirs(input_dir, exist_ok=True)
    os.makedirs(output_dir, exist_ok=True)

    # The worker runs as uid 1000 and must be able to write its report back.
    for path in (job_dir, input_dir, output_dir):
        os.chmod(path, 0o777)

    # The submitted name is attacker-controlled. Keep it in metadata for the analysis
    # (the name itself is evidence) but never let it steer where we write.
    safe = "".join(c for c in os.path.basename(filename) if c.isalnum() or c in "._- ")[:120]
    sample_path = os.path.join(input_dir, safe or "sample.bin")
    with open(sample_path, "wb") as fh:
        fh.write(content)
    os.chmod(sample_path, 0o755)
    return job_dir


def _peek_family(job_id: str) -> str:
    """Cheap pre-spawn triage: just enough to pick the worker image.

    Full triage happens in the worker; here we only need to know whether to hand the job
    to the Wine image. A DOS/PE header whose e_lfanew points at a PE signature is a PE.
    """
    input_dir = os.path.join(settings.jobs_dir, job_id, "input")
    try:
        names = [n for n in os.listdir(input_dir)
                 if os.path.isfile(os.path.join(input_dir, n))]
    except OSError:
        return ""
    if not names:
        return ""
    try:
        with open(os.path.join(input_dir, names[0]), "rb") as fh:
            head = fh.read(4096)
    except OSError:
        return ""
    if head[:2] == b"MZ" and len(head) >= 0x40:
        e_lfanew = int.from_bytes(head[0x3C:0x40], "little")
        if 0 < e_lfanew < len(head) - 4 and head[e_lfanew:e_lfanew + 4] == b"PE\x00\x00":
            return "pe"
    return ""


def _select_image(family: str) -> str:
    if settings.ENABLE_WINE and family in ("pe",):
        try:
            client().images.get(settings.WORKER_IMAGE_WINE)
            return settings.WORKER_IMAGE_WINE
        except ImageNotFound:
            log.warning("ENABLE_WINE is set but %s is missing; falling back to %s",
                        settings.WORKER_IMAGE_WINE, settings.WORKER_IMAGE)
    return settings.WORKER_IMAGE


def run_worker(job_id: str, declared_name: str, family_hint: str = "") -> dict:
    """Run one detonation container to completion. Returns execution metadata."""
    host_job_dir = settings.host_job_dir(job_id)
    image = _select_image(family_hint or _peek_family(job_id))
    dns = _fakenet_ip()

    meta: dict = {
        "image": image,
        "network": settings.DETONATION_NETWORK,
        "dns": dns,
        "started_at": datetime.now(timezone.utc).isoformat(),
    }

    kwargs = dict(
        image=image,
        name=f"sbx-worker-{job_id[:12]}",
        detach=True,

        # --- isolation -------------------------------------------------------
        network=settings.DETONATION_NETWORK,   # internal: no route off the host
        dns=[dns] if dns else None,            # every lookup lands on the sink
        user="1000:1000",
        cap_drop=["ALL"],
        # Only ptrace is added back, and only because strace is how we observe behaviour.
        cap_add=["SYS_PTRACE"],
        security_opt=["no-new-privileges:true", "seccomp=unconfined"],
        read_only=True,                        # rootfs is immutable
        tmpfs={
            "/tmp": "rw,noexec,nosuid,size=256m",
            "/home/analyst": "rw,size=64m",
        },

        # --- resource ceilings ----------------------------------------------
        mem_limit=settings.WORKER_MEMORY,
        memswap_limit=settings.WORKER_MEMORY,  # equal to mem_limit disables swap
        nano_cpus=int(settings.WORKER_CPUS * 1e9),
        pids_limit=settings.WORKER_PIDS_LIMIT,

        # --- job wiring ------------------------------------------------------
        volumes={host_job_dir: {"bind": "/job", "mode": "rw"}},
        environment={
            "JOB_DIR": "/job",
            "WORK_DIR": "/tmp/work",
            "DETONATE": "1",
            "DETONATION_SECONDS": str(settings.DETONATION_SECONDS),
            "DECLARED_NAME": declared_name,
            "ENABLE_WINE": "1" if image == settings.WORKER_IMAGE_WINE else "0",
            "HOME": "/home/analyst",
        },
        labels={"sbx.job": job_id, "sbx.role": "worker"},
    )

    # /tmp must stay executable when we actually detonate something there.
    kwargs["tmpfs"]["/tmp"] = "rw,nosuid,size=256m"

    # The Wine worker is a special case. Wine needs to write to its ~1.3 GB prefix at
    # runtime, which a read-only rootfs forbids and a 64 MiB home tmpfs would shadow. So
    # for this image only we drop read_only and the home tmpfs, letting Wine use the
    # prefix baked into the (disposable, --rm) container layer. Every other control is
    # unchanged: still non-root, every capability dropped, no route off the host,
    # memory/PID/CPU-capped, wall-clock-killed, and the tooling under /opt/worker stays
    # unwritable via its mode bits. The container is destroyed after the job regardless.
    if image == settings.WORKER_IMAGE_WINE:
        kwargs["read_only"] = False
        kwargs["tmpfs"].pop("/home/analyst", None)

    container = None
    started = time.monotonic()
    try:
        container = client().containers.run(**kwargs)
        container.reload()
        try:
            meta["worker_ip"] = (container.attrs["NetworkSettings"]["Networks"]
                                 [settings.DETONATION_NETWORK]["IPAddress"])
        except KeyError:
            meta["worker_ip"] = None

        try:
            result = container.wait(timeout=settings.JOB_TIMEOUT)
            meta["exit_code"] = result.get("StatusCode")
            meta["timed_out"] = False
        except Exception:
            # Covers both the requests read-timeout and any docker-side wait failure.
            meta["timed_out"] = True
            meta["exit_code"] = None
            log.warning("job %s exceeded %ss; killing worker", job_id, settings.JOB_TIMEOUT)
            try:
                container.kill()
            except (APIError, NotFound):
                pass

        try:
            meta["logs"] = container.logs(tail=200).decode("utf-8", "replace")[-4000:]
        except (APIError, NotFound):
            meta["logs"] = ""

    except ImageNotFound:
        meta["error"] = (f"worker image {image} is not built. Run `make build` first.")
    except APIError as exc:
        meta["error"] = f"docker API error: {exc}"
    finally:
        if container is not None:
            try:
                container.remove(force=True)     # nothing from a job outlives the job
            except (APIError, NotFound):
                pass

    meta["wall_seconds"] = round(time.monotonic() - started, 2)
    meta["finished_at"] = datetime.now(timezone.utc).isoformat()
    return meta


def read_observations(job_id: str) -> dict | None:
    path = os.path.join(settings.jobs_dir, job_id, "output", "observations.json")
    try:
        with open(path, "r", encoding="utf-8") as fh:
            return json.load(fh)
    except (FileNotFoundError, json.JSONDecodeError) as exc:
        log.warning("job %s: could not read observations: %s", job_id, exc)
        return None


def collect_network(worker_ip: str | None, started_at: str, finished_at: str) -> dict:
    """Pull this worker's flows out of the fakenet log.

    Matching is by source IP within the job's own time window: the IP alone is not enough
    because Docker recycles addresses between jobs.
    """
    empty = {"dns_queries": [], "http_requests": [], "tcp_sessions": [],
             "connect_attempts": [], "contacted_hosts": []}
    if not worker_ip:
        return empty

    try:
        start = datetime.fromisoformat(started_at)
        end = datetime.fromisoformat(finished_at)
    except (TypeError, ValueError):
        return empty

    dns, http, tcp = [], [], []
    try:
        with open(settings.net_log, "r", encoding="utf-8") as fh:
            for line in fh:
                try:
                    event = json.loads(line)
                except json.JSONDecodeError:
                    continue
                if event.get("src") != worker_ip:
                    continue
                try:
                    when = datetime.fromisoformat(event["ts"])
                except (KeyError, ValueError):
                    continue
                if not (start <= when <= end):
                    continue
                kind = event.get("kind")
                if kind == "dns":
                    dns.append(event)
                elif kind in ("http", "http_connect"):
                    http.append(event)
                elif kind == "tcp":
                    tcp.append(event)
    except FileNotFoundError:
        return empty

    hosts = {e.get("qname") for e in dns if e.get("qname")}
    hosts |= {e.get("host") for e in http if e.get("host")}
    return {
        "dns_queries": dns[:120],
        "http_requests": http[:120],
        "tcp_sessions": tcp[:120],
        "connect_attempts": [],       # filled in from the strace side by the caller
        "contacted_hosts": sorted(h for h in hosts if h),
    }


def cleanup_old_jobs(max_age_hours: int | None = None) -> int:
    """Delete job directories past the retention window. Returns how many were removed."""
    max_age = (max_age_hours or settings.JOB_RETENTION_HOURS) * 3600
    now = time.time()
    removed = 0
    if not os.path.isdir(settings.jobs_dir):
        return 0
    for name in os.listdir(settings.jobs_dir):
        path = os.path.join(settings.jobs_dir, name)
        try:
            if os.path.isdir(path) and now - os.path.getmtime(path) > max_age:
                shutil.rmtree(path, ignore_errors=True)
                removed += 1
        except OSError:
            continue
    return removed


def reap_orphans() -> int:
    """Kill any worker container left behind by a crashed API process."""
    killed = 0
    try:
        for container in client().containers.list(
            all=True, filters={"label": "sbx.role=worker"}
        ):
            try:
                container.remove(force=True)
                killed += 1
            except (APIError, NotFound):
                continue
    except APIError:
        pass
    return killed
