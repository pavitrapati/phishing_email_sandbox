#!/usr/bin/env python3
"""Worker entrypoint. Runs inside the disposable detonation container.

Contract with the orchestrator:
    reads   /job/input/<the one sample file>
    writes  /job/output/observations.json   (+ /job/output/artifacts/*)
    exit 0 whenever a report was written -- even a failed analysis is a result, and a
    non-zero exit would make the orchestrator throw away evidence it already has.

This process never scores anything. It records what it saw and hands that to the API.
"""
from __future__ import annotations

import json
import os
import sys
import time
import traceback
from datetime import datetime, timezone

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from analyzers import archive, behavior, common, office, pdf, pe, script, triage  # noqa: E402

JOB_DIR = os.environ.get("JOB_DIR", "/job")
INPUT_DIR = os.path.join(JOB_DIR, "input")
OUTPUT_DIR = os.path.join(JOB_DIR, "output")
ARTIFACT_DIR = os.path.join(OUTPUT_DIR, "artifacts")
WORK_DIR = os.environ.get("WORK_DIR", "/tmp/work")

DETONATE = os.environ.get("DETONATE", "1") == "1"
BUDGET = int(os.environ.get("DETONATION_SECONDS", "45"))
DECLARED_NAME = os.environ.get("DECLARED_NAME", "")

OFFICE_FAMILIES = {"ole_office", "ole", "ooxml_word", "ooxml_excel",
                   "ooxml_powerpoint", "ooxml_other", "rtf", "msg"}
ARCHIVE_FAMILIES = {"zip", "rar", "7z", "gzip", "bzip2", "xz", "cab", "iso", "jar"}
PE_FAMILIES = {"pe", "elf"}


def _find_sample() -> str:
    entries = [os.path.join(INPUT_DIR, n) for n in sorted(os.listdir(INPUT_DIR))]
    files = [p for p in entries if os.path.isfile(p)]
    if not files:
        raise FileNotFoundError(f"no sample file in {INPUT_DIR}")
    return files[0]


def _detonate_pe(path: str, tri: dict, artifact_dir: str) -> dict:
    """Wine for PE, native execution for ELF -- both under strace, both opt-in for PE."""
    if tri["family"] == "elf":
        # The input file is owned by root (written by the orchestrator) and mode 0o444.
        # The worker runs as uid 1000 so it cannot chmod the original.  Copy to the
        # writable scratch space, make it executable there, and execute the copy.
        import shutil
        exec_copy = os.path.join(WORK_DIR, os.path.basename(path))
        shutil.copy2(path, exec_copy)
        os.chmod(exec_copy, 0o755)
        return behavior.execute([exec_copy], WORK_DIR, artifact_dir, BUDGET, label="elf")

    if os.environ.get("ENABLE_WINE") == "1":
        import shutil
        import subprocess
        if not shutil.which("wine"):
            return {"executed": False, "engine": "wine",
                    "error": "ENABLE_WINE=1 but wine is not present in this image; "
                             "build the wine worker image with `make build-wine`"}
                             
        # /home/analyst is mounted as a tmpfs, which shadows the .wine prefix created during image build.
        # Restore the fully-initialized prefix from /opt/wineprefix to avoid a 5-10s initialization 
        # penalty on every run and to restore our custom injector/hook DLLs.
        wine_prefix = os.environ.get("WINEPREFIX", "/home/analyst/.wine")
        if os.path.isdir("/opt/wineprefix") and not os.path.exists(os.path.join(wine_prefix, "system.reg")):
            shutil.copytree("/opt/wineprefix", wine_prefix, dirs_exist_ok=True)
                             
        # Start Xvfb
        xvfb = subprocess.Popen(["Xvfb", ":99", "-screen", "0", "1024x768x24"])
        # Start mouse simulation
        mouse_sim = subprocess.Popen(["/opt/worker/simulate_mouse.sh"], env={"DISPLAY": ":99"})
        
        wine_env = {"WINEDEBUG": "-all", "WINEPREFIX": "/home/analyst/.wine",
                     "DISPLAY": ":99"}
        
        # Copy the target into a realistic Windows path on the Wine C: drive.
        # Using Z:\home\analyst\ triggers al-khaser's injected-library detection.
        desktop_dir = os.path.join(wine_prefix, "drive_c", "users", "analyst", "Desktop")
        os.makedirs(desktop_dir, exist_ok=True)
        target_linux = os.path.join(desktop_dir, "target.exe")
        shutil.copyfile(path, target_linux)
        os.chmod(target_linux, 0o755)
        wine_target_path = "C:\\\\users\\\\analyst\\\\Desktop\\\\target.exe"
        
        # Install our proxy powrprof.dll into system32 so it looks like a real
        # system DLL, not an injected library in a non-standard path.
        hook_dll = os.path.join(wine_prefix, "drive_c", "powrprof.dll")
        sys32_dir = os.path.join(wine_prefix, "drive_c", "windows", "system32")
        if os.path.exists(hook_dll):
            # Rename Wine's built-in to powrprof_real.dll, then install our proxy
            real_powrprof = os.path.join(sys32_dir, "powrprof.dll")
            real_powrprof_bak = os.path.join(sys32_dir, "powrprof_real.dll")
            if os.path.exists(real_powrprof) and not os.path.exists(real_powrprof_bak):
                shutil.move(real_powrprof, real_powrprof_bak)
            shutil.copyfile(hook_dll, real_powrprof)
            wine_env["WINEDLLOVERRIDES"] = "powrprof=n,b"
            
        cmd = ["wine", wine_target_path]
        
        try:
            return behavior.execute(
                cmd, WORK_DIR, artifact_dir, BUDGET, label="wine",
                env=wine_env,
            )
        finally:
            mouse_sim.terminate()
            xvfb.terminate()

    return {
        "executed": False,
        "engine": "static-only",
        "reason": "PE detonation is disabled. Windows binaries need Windows semantics; "
                  "this image reports PE structure, imports, packing and embedded payloads "
                  "statically. Set ENABLE_WINE=1 (after `make build-wine`) for a Wine run.",
    }


def analyze_sample(path: str, declared_name: str) -> dict:
    observations: dict = {"errors": [], "timings": {}}

    started = time.monotonic()
    tri = triage.triage(path, declared_name or os.path.basename(path))
    observations["file"] = tri
    observations["timings"]["triage"] = round(time.monotonic() - started, 3)

    family = tri["family"]
    observations["routing"] = {"family": family, "label": tri["label"]}

    def timed(name: str, fn):
        mark = time.monotonic()
        try:
            return fn()
        except Exception as exc:
            observations["errors"].append({
                "stage": name, "error": f"{type(exc).__name__}: {exc}",
                "traceback": traceback.format_exc()[-2000:],
            })
            return {"engine": name, "error": str(exc)}
        finally:
            observations["timings"][name] = round(time.monotonic() - mark, 3)

    if family in OFFICE_FAMILIES:
        static = timed("office", lambda: office.analyze(path, tri))
        observations["static"] = static
        if DETONATE:
            observations["dynamic"] = timed("office_emulate", lambda: office.emulate(path, tri, static, WORK_DIR, BUDGET))
        else:
            observations["dynamic"] = {
                "executed": False, "engine": "static-only",
                "reason": "detonation disabled for this job",
            }

    elif family == "pdf":
        static = timed("pdf", lambda: pdf.analyze(path, tri))
        observations["static"] = static
        # Embedded PDF JavaScript is a real script -- emulate it rather than just reading it.
        js_blobs = static.get("javascript", []) if isinstance(static, dict) else []
        if DETONATE and js_blobs:
            def _emulate_pdf_js():
                js_path = os.path.join(WORK_DIR, "embedded.js")
                with open(js_path, "w", encoding="utf-8") as fh:
                    fh.write("\n\n".join(js_blobs))
                return script._run_boxjs(js_path, WORK_DIR, ARTIFACT_DIR, BUDGET)
            observations["dynamic"] = timed("pdf_js", _emulate_pdf_js)
            observations["dynamic"]["note"] = ("emulated the JavaScript extracted from the "
                                               "PDF, not the PDF itself")
        else:
            observations["dynamic"] = {
                "executed": False, "engine": "static-only",
                "reason": "no embedded JavaScript to emulate" if not js_blobs
                          else "detonation disabled for this job",
            }

    elif family in ARCHIVE_FAMILIES:
        observations["static"] = timed(
            "archive", lambda: archive.analyze(path, tri, WORK_DIR))
        observations["dynamic"] = {
            "executed": False, "engine": "unpack-and-triage",
            "reason": "archive contents are extracted and triaged one level deep; each child "
                      "is reported with its true type so the caller can resubmit any child "
                      "for its own detonation",
        }

    elif family in PE_FAMILIES:
        observations["static"] = timed("pe", lambda: pe.analyze(path, tri))
        observations["dynamic"] = (
            timed("pe_detonate", lambda: _detonate_pe(path, tri, ARTIFACT_DIR))
            if DETONATE else
            {"executed": False, "reason": "detonation disabled for this job"}
        )

    elif family in ("js", "vbs", "wsf", "hta", "ps1", "bat", "sh", "py", "pl", "rb"):
        result = timed("script", lambda: script.analyze(
            path, tri, WORK_DIR, ARTIFACT_DIR, BUDGET, detonate=DETONATE))
        observations["dynamic"] = result.pop("dynamic", {"executed": False})
        observations["static"] = result

    else:
        with open(path, "rb") as fh:
            raw = fh.read(8 * 1024 * 1024)
        observations["static"] = {
            "engine": "generic",
            "note": f"no specialised analyzer for family '{family}'; reporting generic "
                    f"content indicators only",
            "strings_sample": common.strings(raw, limit=200),
            "file_iocs": common.extract_iocs(raw),
            "entropy": common.entropy(raw),
        }
        observations["dynamic"] = {"executed": False, "engine": "none",
                                   "reason": f"unrecognised file family '{family}'"}

    return observations


def main() -> int:
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    os.makedirs(ARTIFACT_DIR, exist_ok=True)
    os.makedirs(WORK_DIR, exist_ok=True)

    report = {
        "schema_version": "1.0",
        "worker_started": datetime.now(timezone.utc).isoformat(),
        "detonation_enabled": DETONATE,
        "detonation_budget_seconds": BUDGET,
    }
    overall = time.monotonic()

    try:
        sample = _find_sample()
        report["observations"] = analyze_sample(sample, DECLARED_NAME)
        report["status"] = "completed"
    except Exception as exc:
        report["status"] = "failed"
        report["error"] = f"{type(exc).__name__}: {exc}"
        report["traceback"] = traceback.format_exc()[-4000:]

    report["worker_finished"] = datetime.now(timezone.utc).isoformat()
    report["worker_seconds"] = round(time.monotonic() - overall, 2)

    out_path = os.path.join(OUTPUT_DIR, "observations.json")
    tmp_path = out_path + ".tmp"
    # Write-then-rename: the orchestrator must never read a half-written report.
    with open(tmp_path, "w", encoding="utf-8") as fh:
        json.dump(report, fh, indent=2, default=str)
    os.replace(tmp_path, out_path)

    print(f"[worker] {report['status']} in {report['worker_seconds']}s -> {out_path}",
          file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
