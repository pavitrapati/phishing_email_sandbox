from __future__ import annotations

import os


def _int(name: str, default: int) -> int:
    try:
        return int(os.environ.get(name, default))
    except (TypeError, ValueError):
        return default


def _float(name: str, default: float) -> float:
    try:
        return float(os.environ.get(name, default))
    except (TypeError, ValueError):
        return default


class Settings:
    # Path to the shared data dir, as seen from inside this container...
    DATA = os.environ.get("SANDBOX_DATA", "/data")
    # ...and as the Docker daemon sees it on the host. Worker bind mounts are resolved by
    # the daemon on the host, so it must be given the real host path, not ours.
    HOST_DATA = os.environ.get("SANDBOX_HOST_DATA", "")

    WORKER_IMAGE = os.environ.get("WORKER_IMAGE", "sbx-worker:latest")
    WORKER_IMAGE_WINE = os.environ.get("WORKER_IMAGE_WINE", "sbx-worker-wine:latest")
    DETONATION_NETWORK = os.environ.get("DETONATION_NETWORK", "sbx_detonation")
    FAKENET_HOST = os.environ.get("FAKENET_HOST", "fakenet")

    ENABLE_WINE = os.environ.get("ENABLE_WINE", "0") == "1"
    JOB_TIMEOUT = _int("JOB_TIMEOUT_SECONDS", 180)
    DETONATION_SECONDS = _int("DETONATION_SECONDS", 45)

    WORKER_MEMORY = os.environ.get("WORKER_MEMORY", "768m")
    WORKER_CPUS = _float("WORKER_CPUS", 1.0)
    WORKER_PIDS_LIMIT = _int("WORKER_PIDS_LIMIT", 256)

    MAX_UPLOAD_BYTES = _int("MAX_UPLOAD_BYTES", 50 * 1024 * 1024)
    MAX_CONCURRENT_JOBS = _int("MAX_CONCURRENT_JOBS", 4)
    JOB_RETENTION_HOURS = _int("JOB_RETENTION_HOURS", 24)

    API_KEY = os.environ.get("API_KEY", "").strip()
    LOG_LEVEL = os.environ.get("LOG_LEVEL", "INFO").upper()

    @property
    def jobs_dir(self) -> str:
        return os.path.join(self.DATA, "jobs")

    @property
    def net_log(self) -> str:
        return os.path.join(self.DATA, "net", "events.jsonl")

    def host_job_dir(self, job_id: str) -> str:
        if not self.HOST_DATA:
            raise RuntimeError(
                "SANDBOX_HOST_DATA is unset. The Docker daemon resolves worker bind mounts "
                "on the host, so the API must be told the absolute host path of ./data. "
                "Set it in .env -- see .env.example."
            )
        return os.path.join(self.HOST_DATA, "jobs", job_id)


settings = Settings()
