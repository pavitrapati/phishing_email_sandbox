# Phishing Attachment Detonation Sandbox — Architecture

## Purpose
Give the GPT-4o analysis backend a **structured, factual behaviour report** for any email
attachment, so the model reasons over observed evidence instead of guessing from a filename.

The sandbox is a **standalone HTTP microservice**. The backend POSTs a file, polls for
completion, and receives JSON. It never needs Docker knowledge of its own.

## Trust model
The attachment is assumed hostile. Every design choice follows from that:

| Threat | Mitigation |
|---|---|
| Sample escapes to the internet / phones home | Detonation network is `internal: true` (no NAT, no route off-host). DNS is hijacked to the fakenet sink. |
| Sample attacks the analysis API | Sample never runs in the API container. Worker containers are spawned per-job and are on a different network than the API's published port. |
| Sample escapes the container | `cap_drop: ALL` (only `SYS_PTRACE` added back for tracing), `no-new-privileges`, non-root uid 1000, read-only rootfs with tmpfs scratch, default seccomp + AppArmor retained. |
| Sample exhausts the host | Hard `mem_limit`, `pids_limit`, `nano_cpus` quota, and a wall-clock kill enforced by the orchestrator. |
| Sample poisons later jobs | Container is `--rm`; each job gets its own host directory bound at `/job`. Nothing is shared between jobs. |
| Sample reads other jobs' data | Per-job bind mount only — the worker cannot see the jobs volume root. |

**Explicitly not claimed:** this is a container sandbox, not a hypervisor. A kernel 0-day
escapes it. For untrusted real-world malware at scale, run the whole stack in a
disposable VM. This is stated plainly in the README rather than hidden.

## Components

```
                 host :8090
                     │
        ┌────────────▼─────────────┐
        │  sbx-api  (FastAPI)      │   net: sbx_control  +  sbx_detonation
        │  orchestrator, scoring   │   /var/run/docker.sock (spawns workers)
        └────────┬─────────────────┘
                 │ docker API
                 ▼
        ┌──────────────────────────┐
        │  sbx-worker-<job_id>     │   net: sbx_detonation  (internal, no egress)
        │  static + detonation     │   dns → fakenet
        │  --rm, caps dropped      │   bind: data/jobs/<id> → /job
        └────────┬─────────────────┘
                 │ all DNS + resulting TCP
                 ▼
        ┌──────────────────────────┐
        │  sbx-fakenet             │   wildcard DNS, HTTP/HTTPS sink,
        │  simulated internet      │   generic TCP sinks, JSONL flow log
        └──────────────────────────┘
```

### Networks
- `sbx_control` — bridge. Only the API publishes a port here. Fakenet joins it purely so
  the API can reach its control endpoint; fakenet publishes nothing.
- `sbx_detonation` — `internal: true`. **No route to the real internet exists at all.**
  Workers and fakenet live here.

### How the "simulated internet" works
Workers are started with `--dns <fakenet-ip>`. Fakenet answers **every** A/AAAA query with
its own address, so any domain-based C2 lands on the sink, which speaks HTTP, HTTPS
(self-signed), and a generic banner-less TCP sink on the common malware ports. Every DNS
query, HTTP request (method, host, path, headers, body) and raw TCP connect is appended to
`data/net/events.jsonl` with a source IP and timestamp.

Raw-IP C2 (no DNS) has nowhere to go on an `internal` network — those attempts are captured
from the worker's own `connect()` syscalls instead, so they still appear in the report as
`network.tcp_connects`. Both paths are covered; neither reaches the real internet.

### Detonation engines
The orchestrator picks an engine from the triaged file type:

| Family | Static | Dynamic |
|---|---|---|
| Office (doc/docx/xls/xlsm/ppt, OLE + OOXML) | `olevba`, `msodde`, `oleobj`, relationship/remote-template scan | VBA deobfuscation + emulated `Auto_Open` string/IOC extraction |
| PDF | structure walk via `pikepdf`, `/OpenAction`, `/Launch`, `/JS`, embedded files, URI actions | embedded JS run under the JS emulator |
| Scripts (js/jse/vbs/wsf/hta/ps1/bat/sh/py) | deobfuscation, entropy, string extraction | `box-js` WScript emulation (js/vbs/wsf/hta) or native execution under `strace` |
| Archives (zip/7z/rar/iso/img/cab/gz/tar) | recursive unpack, per-child triage, password-protected detection, decoy-extension detection | children recursed one level and detonated by their own engine |
| PE (exe/dll/msi) | `pefile`: sections, entropy, imports, resources, overlay, packer heuristics, signature presence | Wine under `strace` **only when `ENABLE_WINE=1`** (opt-in image, see README) |
| ELF / native | `readelf`-style parse | direct execution under `strace` |

`strace` gives us process tree (`execve`, `clone`), file writes (`openat` with `O_WRONLY`/
`O_CREAT`), deletions (`unlink`), permission changes (`chmod`), and outbound connections
(`socket`/`connect`) — the four behaviour classes that actually matter for a phishing verdict.

### Separation of observation and judgement
The **worker only observes** — it emits raw facts and never scores. The **API scores**,
using a declarative signature set in `services/api/app/signatures.py`. This means detection
rules can be tuned and redeployed without rebuilding the (large) worker image, and the same
raw observation set can be re-scored retroactively.

### Report contract
`schema_version: "1.0"`. The field the GPT-4o backend most wants is `llm_summary` — a
compact prose brief of the evidence, safe to paste directly into a prompt, with all URLs
and IPs defanged (`hxxp://`, `1[.]2[.]3[.]4`) so nothing in the pipeline auto-links or
auto-fetches an attacker-controlled address. The full structured detail stays available
in the sibling fields for the UI.

## Job lifecycle
1. `POST /v1/analyze` (multipart) → job dir created, sample written, `202` + `job_id`.
2. Orchestrator (background task) triages, selects image + engine, spawns the worker.
3. Worker runs static passes, then detonates with a wall-clock budget, writes `/job/output/report.json`.
4. Orchestrator waits with a hard timeout, kills+removes the container, merges the worker
   report with the fakenet flows for that worker IP and time window.
5. Signature engine scores → `verdict`. Report cached; `GET /v1/report/{job_id}` serves it.
6. `POST /v1/analyze/sync` does all of the above in one blocking call for simple backends.
