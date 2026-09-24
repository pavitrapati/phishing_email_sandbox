# Sandbox Test Report

_Generated 2026-09-09 15:47 · Docker version 29.1.3, build 29.1.3-0ubuntu3~24.04.2 · host Linux 6.8_

## Summary

| Suite | Passed | Failed | What it covers |
|---|---:|---:|---|
| Unit (`make test-unit`) | 69 | 0 | analyzers + scoring, in the worker image, no daemon |
| Integration (`make test-integration`) | 13 | 0 | full detonation of every sample against the live stack |
| Isolation (`make verify-isolation`) | 9 | 0 | containment claims (network egress, privilege, FS) |
| **Total** | **91** | **0** | |

**Result: ALL PASSED**

## Integration — per-sample verdicts

Each sample is submitted to `POST /v1/analyze/sync` and detonated in its own container.

| Sample | Expected | Result | Verdict | Score | Signatures fired |
|---|---|:--:|---|--:|---|
| `benign_report.pdf` | benign | ✅ | benign | 0 | — |
| `meeting_notes.txt` | benign | ✅ | benign | 0 | — |
| `invoice_scan.pdf` | malicious | ✅ | malicious | 90 | PDF_LAUNCH_ACTION, PDF_AUTO_ACTION, IOC_EXECUTABLE_URL, PDF_JAVASCRIPT |
| `payment_advice.docx` | malicious | ✅ | malicious | 84 | OFFICE_REMOTE_TEMPLATE, OFFICE_EXTERNAL_REL |
| `invoice_2024.doc` | malicious | ✅ | malicious | 84 | OFFICE_MACRO_SHELL, OFFICE_MACRO_AUTOEXEC, OFFICE_MACRO_OBFUSCATED, OFFICE_MACRO_PRESENT |
| `shipping_documents.zip` | suspicious+ | ✅ | malicious | 85 | ARCHIVE_DECOY_NAME, ARCHIVE_DANGEROUS_CONTENT, ARCHIVE_CHILD_MISMATCH |
| `invoice_details.js` | suspicious+ | ✅ | malicious | 92 | SCRIPT_DROPPER_BEHAVIOUR, SCRIPT_ENCODED_PAYLOAD, SCRIPT_OBFUSCATED, DANGEROUS_EXTENSION |
| `update_helper.sh` | suspicious+ | ✅ | malicious | 94 | DYN_PERSISTENCE, DYN_DROPPED_EXECUTABLE, DYN_LOLBIN, DYN_NETWORK, DYN_PROCESS_SPAWN, DANGEROUS_EXTENSION |
| `SecurityUpdate.scr` | suspicious+ | ✅ | malicious | 82 | PE_EMBEDDED_EXECUTABLE, PE_SELF_MODIFYING, PE_PACKED, DANGEROUS_EXTENSION, PE_FAKE_TIMESTAMP, PE_UNSIGNED |

## Integration — behavioural & safety checks

- ✅ async job 1294969471fe4dac9dcba9285a62d5ec completed
- ✅ captured: dns,http,raw-ip-connect
- ✅ all summaries defanged and reasonably sized
- ✅ no leftover worker containers

## Isolation checks (`make verify-isolation`)

```
bash tests/verify_isolation.sh
Isolation checks against network 'sbx_detonation':

[1] The detonation network must have no route to the internet
  PASS  raw TCP to 1.1.1.1:53 is blackholed
  PASS  raw TCP to 8.8.8.8:443 is blackholed
  PASS  HTTP to a real host fails

[2] The network is marked internal in Docker's own view
  PASS  docker reports sbx_detonation as internal

[3] DNS must resolve to the fakenet sink, not to the real answer
  PASS  arbitrary domain resolves to the sink (172.31.240.53)

[4] The worker must not be able to escalate or write to its own tooling
  PASS  cannot write to /opt/worker
  PASS  cannot write to the read-only rootfs
  PASS  runs as uid 1000, not root
  PASS  cannot re-acquire privileges via a setuid binary

-------------------------------------------
  9 passed, 0 failed
```

## Unit test detail

<details><summary>Full unit output (69 passed, 0 failed)</summary>

```
docker run --rm --network none \
  -v "/media/mrgrin69/D/programming_languages/phishing_email_sandbox/tests:/tests:ro" \
  -v "/media/mrgrin69/D/programming_languages/phishing_email_sandbox/services/api:/api:ro" \
  --entrypoint python sbx-worker:latest /tests/test_unit.py

common: indicator extraction and entropy
  PASS  extracts URLs
  PASS  extracts emails
  PASS  extracts IPs
  PASS  filters OOXML schema noise from domains
  PASS  entropy of uniform data is near zero
  PASS  entropy of random data is high
  PASS  run() reports a missing tool instead of raising

triage: type identification and name deception
  PASS  identifies PDF
  PASS  no mismatch on a correctly named PDF
  PASS  identifies PE
  PASS  flags .scr as a dangerous extension
  PASS  detects content/extension mismatch
  PASS  detects a right-to-left override in the filename
  PASS  detects a double extension
  PASS  identifies OOXML Word
  PASS  identifies a JS script
  PASS  identifies a ZIP archive
  PASS  identifies plain text
  PASS  hashes are populated

pdf: dangerous structures
  PASS  finds JavaScript
  PASS  flags /OpenAction
  PASS  flags /Launch
  PASS  extracts the URI target
  PASS  benign PDF has no JavaScript
  PASS  benign PDF has no /Launch

office: macros and remote templates
  PASS  detects remote template injection
  PASS  lists external relationship targets
  PASS  identifies a legacy OLE Office document
  PASS  finds the auto-execution trigger
  PASS  flags shell/download calls in the macro
  PASS  reconstructs the Chr()-obfuscated string

archive: decoys and dangerous children
  PASS  finds the dangerous .exe entry
  PASS  flags the padded decoy name
  PASS  extracts and re-triages children
  PASS  not reported as password protected

pe: packing, sections, overlay
  PASS  pefile parses the sample
  PASS  recognises the UPX section names
  PASS  flags a writable+executable section
  PASS  detects the embedded PE in the overlay
  PASS  reports the sample as unsigned
  PASS  flags the implausible compile timestamp
  PASS  entry point is outside the code section

script: deobfuscation and encoded payloads
  PASS  reconstructs fromCharCode strings
  PASS  reassembles the split URL
  PASS  decodes the embedded base64 payload
  PASS  finds the C2 domain

behavior: real execution under strace
  PASS  execution succeeded
  PASS  captured the trace
  PASS  recorded a spawned process
  PASS  recorded the file write
  PASS  recorded the chmod to executable
  PASS  recorded the deletion

behavior: the wall-clock budget is enforced
  PASS  times out rather than hanging
  PASS  gives up close to the budget

signatures: scoring behaviour
  PASS  mismatch rule fires
  PASS  a clean sample scores zero
  PASS  ten weak hints do not reach 'malicious'
  PASS  one strong finding reaches 'malicious'
  PASS  score is capped at 100
  PASS  confidence stays within bounds
  PASS  a broken rule does not lose the job

report: defanging and summary assembly
  PASS  defangs an http URL
  PASS  defangs a bare IPv4
  PASS  does not double-defang an IP inside a URL
  PASS  report carries a verdict
  PASS  llm_summary is populated
  PASS  llm_summary contains no live URLs
  PASS  report is JSON-serialisable
  PASS  PDF JS and Launch both fired

============================================================
  69 passed, 0 failed
```
</details>

## How these were produced

```bash
make test-unit          # 1
make up                 # stack must be running for 2 & 3
make test-integration   # 2
make verify-isolation   # 3
```

Raw per-sample report JSON is written to `/tmp/sbx-integration/*.json`, and every job also persists its own report at `data/jobs/<job_id>/output/report.json`.
