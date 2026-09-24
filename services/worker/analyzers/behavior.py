"""Execution tracing.

Everything that actually *runs* goes through here, under strace, with a wall-clock budget
and a process-group kill so nothing survives the trace. We record the four behaviour
classes that decide a phishing verdict:

  processes      what it spawned, with full argv
  files          what it wrote, deleted, or made executable
  network        who it tried to talk to, including raw-IP C2 that never hits DNS
  persistence    the paths and keys it touched that survive a reboot

The DNS side of network activity is captured by fakenet; connect() is captured here.
Together they cover both domain-based and IP-literal C2.
"""
from __future__ import annotations

import os
import re
import shlex
import signal
import socket
import struct
import subprocess
import time

from . import common

TRACED_CALLS = (
    "execve,execveat,clone,clone3,fork,vfork,openat,open,creat,unlink,unlinkat,"
    "rename,renameat,renameat2,chmod,fchmod,fchmodat,connect,socket,sendto,bind,"
    "mkdir,mkdirat,link,linkat,symlink,symlinkat,truncate,ftruncate,dup2,dup3,"
    "ptrace,mount,setuid,setgid,kill,memfd_create,prctl"
)

# Paths a sample writing here is trying to persist or stage a payload.
PERSISTENCE_HINTS = [
    (re.compile(r"/etc/(cron|systemd|init|rc\d?\.d|profile\.d)"), "system-wide autostart"),
    (re.compile(r"/\.config/(autostart|systemd)"), "user autostart"),
    (re.compile(r"/\.(bashrc|bash_profile|profile|zshrc|xinitrc)$"), "shell startup file"),
    (re.compile(r"/\.ssh/(authorized_keys|config)"), "SSH access"),
    (re.compile(r"(?i)\\\\(Start Menu|Startup)\\\\"), "Windows Startup folder"),
    (re.compile(r"(?i)(CurrentVersion\\\\Run|Software\\\\Microsoft\\\\Windows\\\\CurrentVersion)"),
     "Windows Run key"),
    (re.compile(r"(?i)/(appdata|roaming|localappdata|temp|tmp)/"), "staging directory"),
]

LOLBIN = re.compile(
    r"(?i)\b(powershell|pwsh|cmd\.exe|wscript|cscript|mshta|rundll32|regsvr32|certutil|"
    r"bitsadmin|msiexec|installutil|schtasks|wmic|curl|wget|nc|ncat|socat|python[\d.]*|"
    r"perl|ruby|php|bash|sh|base64|xxd|chmod|systemctl|crontab)\b"
)


def _parse_sockaddr(hexblob: str) -> str | None:
    """Turn strace's sockaddr rendering into an ip:port string.

    strace normally prints connect() args readably (sin_addr=inet_addr("1.2.3.4")), so
    that path is handled by regex below; this handles the raw-hex fallback.
    """
    try:
        raw = bytes.fromhex(hexblob)
    except ValueError:
        return None
    if len(raw) < 8:
        return None
    family = struct.unpack("<H", raw[:2])[0]
    if family == socket.AF_INET:
        port = struct.unpack(">H", raw[2:4])[0]
        return f"{socket.inet_ntoa(raw[4:8])}:{port}"
    if family == socket.AF_INET6 and len(raw) >= 24:
        port = struct.unpack(">H", raw[2:4])[0]
        return f"[{socket.inet_ntop(socket.AF_INET6, raw[8:24])}]:{port}"
    return None


# strace -yy annotates the fd as e.g. `3<TCP:[12345]>`, so the fd matcher must allow an
# optional <...> suffix after the number -- without it, every connect() line is missed.
CONNECT_RE = re.compile(
    r'connect\(\d+(?:<[^>]*>)?,\s*\{sa_family=AF_INET6?,\s*sin6?_port=htons\((\d+)\),\s*'
    r'sin6?_addr=inet_(?:pton|addr)\("?([^")]+)"?\)'
)
UNIX_CONNECT_RE = re.compile(
    r'connect\(\d+(?:<[^>]*>)?,\s*\{sa_family=AF_UNIX,\s*sun_path="([^"]*)"')
EXECVE_RE = re.compile(r'execve\("([^"]*)",\s*\[(.*?)\](?:,\s*|\s*\))')
EXECVE_AT_RE = re.compile(r'execveat\(\d+,\s*"([^"]*)",\s*\[(.*?)\]')
OPEN_RE = re.compile(r'openat?\((?:[^,]+,\s*)?"([^"]*)",\s*([A-Z_|0-9x]+)')
UNLINK_RE = re.compile(r'unlinkat?\((?:[^,]+,\s*)?"([^"]*)"')
CHMOD_RE = re.compile(r'f?chmodat?\((?:[^,]+,\s*)?"([^"]*)",\s*(\d+)')
RENAME_RE = re.compile(r'renameat2?\((?:[^,]+,\s*)?"([^"]*)",\s*(?:[^,]+,\s*)?"([^"]*)"')
MEMFD_RE = re.compile(r'memfd_create\("([^"]*)"')

# Written to by the sample itself, not by the interpreter starting up.
NOISE_PREFIXES = (
    "/proc/", "/sys/", "/dev/null", "/dev/urandom", "/dev/random", "/dev/tty",
    "/usr/lib/", "/lib/", "/lib64/", "/etc/ld.so", "/usr/share/zoneinfo",
    "/usr/local/lib/python", "/usr/lib/python", "/etc/localtime", "/dev/pts",
)


def _is_noise(path: str) -> bool:
    return path.startswith(NOISE_PREFIXES)


def parse_trace(trace_path: str, self_argv: list[str]) -> dict:
    """Turn a raw strace log into structured behaviour. Tolerates truncated logs."""
    processes: list[dict] = []
    files_written: list[str] = []
    files_deleted: list[str] = []
    files_renamed: list[dict] = []
    chmods: list[dict] = []
    connects: list[dict] = []
    unix_connects: list[str] = []
    memfds: list[str] = []
    raw_lines = 0

    try:
        with open(trace_path, "r", encoding="utf-8", errors="replace") as fh:
            for line in fh:
                raw_lines += 1
                if raw_lines > 400_000:      # a trace this long is itself the finding
                    break

                if "execve" in line:
                    match = EXECVE_RE.search(line) or EXECVE_AT_RE.search(line)
                    if match and "-1 ENOENT" not in line:
                        argv = [a.strip().strip('"') for a in
                                re.findall(r'"((?:[^"\\]|\\.)*)"', match.group(2))]
                        processes.append({"path": match.group(1), "argv": argv})

                if "connect(" in line:
                    match = CONNECT_RE.search(line)
                    if match:
                        tail = line.rsplit(")", 1)[-1]
                        failed = ("-1 " in tail
                                  and "EINPROGRESS" not in tail
                                  and "EALREADY" not in tail
                                  and "EISCONN" not in tail)
                        connects.append({"ip": match.group(2), "port": int(match.group(1)),
                                         "failed": failed})
                    else:
                        unix = UNIX_CONNECT_RE.search(line)
                        if unix:
                            unix_connects.append(unix.group(1))

                if "open" in line:
                    match = OPEN_RE.search(line)
                    if match:
                        path, flags = match.group(1), match.group(2)
                        if ("O_WRONLY" in flags or "O_RDWR" in flags or "O_CREAT" in flags) \
                                and not _is_noise(path):
                            files_written.append(path)

                if "unlink" in line:
                    match = UNLINK_RE.search(line)
                    if match and not _is_noise(match.group(1)):
                        files_deleted.append(match.group(1))

                if "chmod" in line:
                    match = CHMOD_RE.search(line)
                    if match:
                        mode = match.group(2)
                        chmods.append({"path": match.group(1), "mode": mode,
                                       "makes_executable": any(
                                           d in "1357" for d in mode[-3:])})

                if "rename" in line:
                    match = RENAME_RE.search(line)
                    if match and not _is_noise(match.group(2)):
                        files_renamed.append({"from": match.group(1), "to": match.group(2)})

                if "memfd_create" in line:
                    match = MEMFD_RE.search(line)
                    if match:
                        memfds.append(match.group(1))
    except FileNotFoundError:
        return {"error": "no trace produced", "trace_lines": 0}

    # The launcher process is ours, not the sample's.
    interesting = [p for p in processes if p["argv"] != self_argv]
    # Wine boots an entire fake Windows (wineserver, services.exe, explorer.exe, plugplay,
    # winedevice, ...) around the sample. Those are the analysis harness, not the sample's
    # own behaviour, so drop them -- otherwise every PE looks like it spawned 15 processes.
    interesting = [
        p for p in interesting
        if not re.search(
            r"(?i)(wineserver|wineboot|winemenubuilder|winedevice|plugplay|services\.exe|"
            r"explorer\.exe|svchost\.exe|rpcss|conhost\.exe|start\.exe|"
            r"/usr/lib/wine/wine(64)?$)",
            (p.get("path") or "") + " " + " ".join(p.get("argv", [])))
    ]

    persistence = []
    for path in set(files_written) | {c["path"] for c in chmods}:
        for pattern, meaning in PERSISTENCE_HINTS:
            if pattern.search(path):
                persistence.append({"path": path, "meaning": meaning})
                break

    lolbins = sorted({
        m.group(0).lower()
        for p in interesting
        for m in [LOLBIN.search(os.path.basename(p["path"]) or "")] if m
    })

    return {
        "trace_lines": raw_lines,
        "processes": [
            {"path": p["path"], "command": " ".join(shlex.quote(a) for a in p["argv"])[:800]}
            for p in interesting[:120]
        ],
        "process_count": len(interesting),
        "files_written": common._dedupe(files_written, 200),
        "files_deleted": common._dedupe(files_deleted, 100),
        "files_renamed": files_renamed[:60],
        "made_executable": [c for c in chmods if c["makes_executable"]][:60],
        "tcp_connects": connects[:120],
        "unix_sockets": common._dedupe(unix_connects, 40),
        "anonymous_executables": common._dedupe(memfds, 20),
        "persistence_paths": persistence[:40],
        "lolbins_invoked": lolbins,
    }


def execute(argv: list[str], workdir: str, artifact_dir: str, budget: int,
            env: dict[str, str] | None = None, label: str = "native") -> dict:
    """Run argv under strace with a hard wall-clock budget.

    The child is put in its own process group so a fork bomb or a backgrounded stage 2
    dies with the group rather than outliving the job.
    """
    trace_path = os.path.join(artifact_dir, f"strace-{label}.log")
    stdout_path = os.path.join(artifact_dir, f"stdout-{label}.log")

    command = [
        "strace", "-f", "-qq", "-s", "512", "-yy",
        "-e", f"trace={TRACED_CALLS}",
        "-o", trace_path,
    ]
    # Wine's ntdll uses ptrace internally; heavy ptrace interception by strace
    # causes al-khaser's NtQueryObject(ObjectAllTypesInformation) to crash with
    # a NULL-pointer read.  --seccomp-bpf lets the kernel do the filtering and
    # drastically reduces the ptrace round-trips, eliminating the conflict.
    if label == "wine":
        command.append("--seccomp-bpf")
    command += ["--"] + argv

    started = time.monotonic()
    timed_out = False
    returncode = None

    try:
        with open(stdout_path, "wb") as out:
            proc = subprocess.Popen(
                command, cwd=workdir, stdout=out, stderr=subprocess.STDOUT,
                stdin=subprocess.DEVNULL, start_new_session=True,
                env={**os.environ, **(env or {})},
            )
            try:
                returncode = proc.wait(timeout=budget)
            except subprocess.TimeoutExpired:
                timed_out = True
                # A sample that sleeps out the clock is normal; kill the whole group.
                try:
                    os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
                except (ProcessLookupError, PermissionError):
                    proc.kill()
                proc.wait(timeout=10)
    except FileNotFoundError as exc:
        return {"executed": False, "error": f"cannot execute: {exc}", "engine": label}

    duration = round(time.monotonic() - started, 2)

    stdout_text = ""
    try:
        with open(stdout_path, "rb") as fh:
            stdout_text = fh.read(65536).decode("utf-8", "replace")
    except OSError:
        pass

    behaviour = parse_trace(trace_path, argv)
    behaviour.update({
        "executed": True,
        "engine": label,
        "command": " ".join(shlex.quote(a) for a in argv),
        "exit_code": returncode,
        "timed_out": timed_out,
        "duration_seconds": duration,
        "stdout": common.truncate(stdout_text, 6000),
        "stdout_iocs": common.extract_iocs(stdout_text.encode("utf-8", "replace")),
    })
    return behaviour
