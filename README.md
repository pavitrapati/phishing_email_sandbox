# Phishing Attachment Detonation Sandbox

A self-contained service that **detonates email attachments in an isolated Docker
environment** and returns structured behavioural evidence, designed to feed a GPT-4o (or
any LLM) phishing-analysis backend. The model reasons over *what the file actually did*
instead of guessing from a filename.

```
POST /v1/analyze  (multipart file)  ->  { job_id }
GET  /v1/report/{job_id}            ->  full JSON report  (poll until status is terminal)
POST /v1/analyze/sync               ->  full JSON report  (one blocking call)
```

The report's `llm_summary` field is a compact, **defanged** prose brief you can paste
straight into a prompt. Full structured detail lives alongside it for your UI.

## What it detects

| Attachment family | Static analysis | Dynamic analysis |
|---|---|---|
| **Office** (doc/docx/xls/xlsm/ppt) | VBA extraction + deobfuscation, Excel 4.0 macros, DDE, **remote-template injection**, embedded OLE objects, macro-source recovery when `olevba` is defeated by a malformed project | VBA string/IOC reconstruction |
| **PDF** | `/OpenAction`, `/Launch`, `/JS`, embedded files, URI actions, object-stream inflation | embedded JavaScript emulated under box-js |
| **Scripts** (js/vbs/wsf/hta/ps1/bat/sh/py) | deobfuscation, base64 payload decoding, PowerShell flag analysis | **box-js** WScript emulation, or native execution under `strace` |
| **Archives** (zip/rar/7z/iso/cab/gz) | recursive unpack + per-child triage, password-protection detection, decoy-name & path-traversal detection, zip-bomb guard | children re-triaged one level deep |
| **PE** (exe/dll/scr/msi) | packing/entropy, W+X sections, import capabilities, embedded PE in resources/overlay, signature & timestamp checks | Wine under `strace` (opt-in, see below) |
| **ELF** | header/symbol parse | native execution under `strace` |

A **simulated internet** (fakenet) sinkholes all DNS and answers HTTP/HTTPS/raw-TCP, so a
sample reveals its C2 without anything ever leaving the host.

## Requirements

- Docker Engine 24+ and Docker Compose v2
- ~2 GB disk for images (add ~1.5 GB if you enable Wine)
- Linux host (the detonation model relies on Linux namespaces, seccomp and strace)

## Quick start

```bash
cp .env.example .env
# set SANDBOX_HOST_DATA to the ABSOLUTE host path of ./data (see below)
make build
make up
make samples          # generate the inert test corpus
make test             # unit + end-to-end integration tests
```

Then analyse a file:

```bash
curl -F "file=@/path/to/attachment.docx" http://127.0.0.1:8090/v1/analyze/sync | jq .verdict
```

or from Python:

```python
from client.sandbox_client import SandboxClient
report = SandboxClient("http://127.0.0.1:8090").analyze_path("attachment.docx")
print(report.verdict_line)
prompt_block = report.for_prompt()   # defanged, ready for GPT-4o
```

### `SANDBOX_HOST_DATA` — the one setting you must get right

The API spawns worker containers by talking to the Docker daemon. The daemon resolves the
workers' bind mounts **on the host**, not inside the API container — so it must be told the
real host path of `./data`. Set `SANDBOX_HOST_DATA` in `.env` to the absolute path of the
`data/` directory in this repo. `make up` will refuse to start without it.

## Integrating with your GPT-4o backend

See [`client/example_integration.py`](client/example_integration.py) for a worked example.
The intended shape:

- The **sandbox produces evidence**; **your model produces the judgement.** Hand the model
  `report.for_prompt()` alongside the email headers and body, and let it weigh them
  together. The sandbox cannot see that a sender is a known supplier; your model can.
- The evidence block is wrapped in an untrusted-content fence. A phishing sample may embed
  text intended to manipulate whatever reads it (macro comments, HTTP bodies, filenames) —
  treat everything inside the block as data, never as instructions.
- On a sandbox outage, the client returns an explicit "safety UNKNOWN" block rather than a
  clean verdict, so a failure never reads as benign.

## Real PE detonation (opt-in)

Windows binaries need Windows semantics. By default PE files are analysed **statically**
(structure, imports, packing, embedded payloads) — usually enough for a phishing verdict.
For behavioural PE detonation under Wine:

```bash
make build-wine       # adds ~1.5 GB
# set ENABLE_WINE=1 in .env
make restart
```

Wine is not Windows: it runs many but not all samples, and evasive malware can detect it.
For high-fidelity Windows detonation at scale, run this stack inside a disposable Windows VM.

## Isolation model

The attachment is assumed hostile. See [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) for the
full threat table. In short:

- **No route to the internet.** The detonation network is `internal: true` — Docker
  provides no NAT or gateway off the host at all. DNS is hijacked to the fakenet sink.
- **Least privilege.** Workers run as uid 1000 with **every capability dropped** (only
  `SYS_PTRACE` added back for tracing), `no-new-privileges`, a **read-only root filesystem**,
  and tmpfs scratch. Default seccomp and AppArmor are retained.
- **Bounded blast radius.** Hard memory, PID and CPU ceilings, plus a wall-clock kill.
- **No cross-contamination.** Each job gets its own bind-mounted directory; the worker is
  `--rm`; orphaned workers from a crashed API are reaped on the next startup.

Verify these claims yourself — they are executable:

```bash
make verify-isolation
```

**This is a container sandbox, not a hypervisor.** A kernel 0-day escapes it. For untrusted
real-world malware at scale, run the whole stack inside a throwaway VM. This limitation is
stated plainly rather than hidden.

## Report schema (`schema_version: 1.0`)

```
verdict      { score 0-100, level benign|suspicious|malicious, confidence, summary, top_reasons }
file         { name, size, family, label, md5/sha1/sha256, entropy, extension_mismatch, ... }
signatures   [ { id, name, severity, description, evidence[] } ]   # ranked, most-severe first
iocs         { urls, domains, ips, emails }                        # de-noised of sandbox infra
network      { dns_queries, http_requests, tcp_sessions, connect_attempts, contacted_hosts }
static       { ...engine-specific observations... }
dynamic      { executed, engine, processes, files_written, persistence_paths, ... }
llm_summary  "defanged prose brief, safe to paste into a prompt"
errors       [ { stage, error } ]                                  # analysis gaps, stated openly
```

### Scoring

Detection lives in [`services/api/app/signatures.py`](services/api/app/signatures.py) —
declarative rules, each a pure function of the observations, kept on the API side so they
can be retuned and redeployed without rebuilding the (large) worker image. The same
observation set can be re-scored retroactively.

Scores combine with **rank-decayed saturation**: one strong finding (a remote-template
injection, a resolved dropper URL) is enough to reach *malicious* on its own, while a pile
of individually weak findings can only ever reach *suspicious*. A plain sum would let ten
trivia add up to a false alarm; this does not.

## Make targets

```
make build            build the three images
make build-wine       additionally build the Wine worker for PE detonation
make up / down        start / stop the stack
make samples          (re)generate the inert test corpus
make test             unit + integration
make verify-isolation prove the containment claims
make clean            remove job data
make nuke             stop everything and remove images
```

## Layout

```
services/api/         FastAPI orchestrator + signature engine + report builder
services/worker/      the detonation image: triage + per-family analyzers + strace tracer
services/fakenet/     the simulated internet (DNS/HTTP/TCP sinks + flow log)
client/               drop-in Python client and a GPT-4o integration example
tests/                inert sample generator, unit tests, integration + isolation suites
docs/ARCHITECTURE.md  design and threat model
```

## A note on the test corpus

`tests/make_samples.py` generates **inert** samples: they reproduce the *structure* of
malicious attachments (auto-open macros, `/Launch` actions, decoy extensions, encoded
payloads) but carry no working payload, and every network indicator is an RFC 2606 / RFC
5737 reserved address that can never resolve to a real host. This is the only responsible
way to ship a detection test suite — nothing here can do harm if it leaks.
