# PE / DLL / Embedded-Malware Scenario Test Report

_Generated 2026-09-09 16:23 · Docker 29.1.3 · Wine detonation ENABLED (`ENABLE_WINE=1`)_

This report answers: **will the sandbox handle `.exe`/`.dll` files and obfuscated / embedded
dynamic malware in attachments?** Each scenario below is an **inert** test sample (the PE is a
cross-compiled dropper that only touches RFC-reserved, sinkholed destinations; nothing here
can do harm if it leaks).

## Result summary

| # | Scenario | Detonation mode | Verdict | Executed? | Key signatures |
|--:|---|---|---|:--:|---|
| 1 | `dropper.exe` — raw .exe (real inert dropper) | wine | **malicious (93)** | yes | persistence (runtime), C2 contact (runtime), download+persist+exec imports, spawned process (runtime) |
| 2 | `PrintConfig.dll` — raw .dll attachment | wine | **malicious (76)** | yes | spawned process (runtime), packed/high-entropy, dangerous extension, unsigned |
| 3 | `Statement_2024.exe` — packed/obfuscated .exe (W+X, hi-entropy) | wine | **malicious (79)** | yes | spawned process (runtime), W+X section, packed/high-entropy, dangerous extension |
| 4 | `Quotation.doc` — PE embedded as OLE object in a .doc | static-only | **malicious (75)** | no | OFFICE_EMBEDDED_EXECUTABLE |
| 5 | `Invoice_Documents.zip` — .exe inside a zip | unpack-and-triage | **suspicious (60)** | no | executable in archive |
| 6 | `Payment_Receipt.zip` — decoy double-extension .exe in a zip | unpack-and-triage | **malicious (85)** | no | decoy filename, executable in archive, child type mismatch |
| 7 | `Secure_Invoice.zip` — password-protected zip hiding a PE | unpack-and-triage | **malicious (74)** | no | encrypted archive, executable in archive |
| 8 | `Shipping_Label.zip` — nested zip -> zip -> .exe | unpack-and-triage | **malicious (78)** | no | exe in nested archive, executable in archive |

All 8 scenarios are flagged (7 malicious, 1 suspicious). None slipped through as benign.

## What each scenario proves

- **Raw `.exe` (`dropper.exe`)** — real Windows PE executed under Wine: dropped a file, wrote a
  `Run` key, and **beaconed to its C2** (`update-cdn.example.net` / `GET /gate.php?id=win`),
  all captured by the simulated internet with nothing leaving the host. This is genuine dynamic
  analysis of a Windows binary.
- **Raw `.dll` / packed `.exe`** — detonated under Wine and, independently, flagged statically on
  packing, W+X sections, import capabilities, and missing signature.
- **PE embedded in a `.doc`** — the OLE-package smuggling trick; caught by scanning the document
  bytes for an embedded PE header (`OFFICE_EMBEDDED_EXECUTABLE`).
- **`.exe` in a zip / decoy double-extension / password-protected zip** — archive contents are
  unpacked and re-triaged; a decoy `Receipt.pdf….exe` and an encrypted archive are both flagged.
- **Nested zip → zip → `.exe`** — archives are recursed up to 3 levels, so a payload buried in a
  nested archive is still found (`ARCHIVE_NESTED_EXECUTABLE`).

## Honest limitations (measured, not hypothetical)

- **`.exe`-in-a-zip scores *suspicious* (60), not *malicious*.** Archive children get triage-level
  flagging, not full PE capability analysis, so a bare executable in a zip is flagged but not
  escalated. Resubmit the extracted child on its own for a full PE verdict.
- **Wine is not Windows.** It ran the inert dropper faithfully, but evasive malware can detect
  Wine and stay dormant; some real samples won't run at all. High-fidelity Windows behaviour needs
  a Windows VM. PE **static** analysis (packing, imports, embedded payloads) runs regardless and is
  usually enough for a phishing verdict.
- **A "clean" dynamic result means "didn't misbehave in this environment in 45s," not "safe."**
  Anti-sandbox sleeps, VM checks, and multi-stage triggers can suppress behaviour.

## Isolation still holds with detonation enabled

`make verify-isolation`: **9 passed, 0 failed** — no internet route, DNS sinkholed, uid 1000,
all capabilities dropped, no privilege escalation. (The Wine worker relaxes only the read-only
rootfs — so Wine can write its prefix — while keeping every other control; it remains disposable
and network-isolated.)

## Regression check

Core suites re-run with Wine enabled: **unit 69/0**, **integration 13/0**. No regressions from the
detection additions (nested-archive recursion, embedded-PE scan, URL-extraction hardening, Wine
process-noise filtering).

## Reproduce

```bash
make pe-scenarios          # cross-compiles the inert PE + builds all scenario samples
# set ENABLE_WINE=1 in .env; make build-wine; make restart
for f in tests/samples/{dropper.exe,PrintConfig.dll,Quotation.doc,Shipping_Label.zip}; do
  curl -sF "file=@$f" http://127.0.0.1:8090/v1/analyze/sync | jq '.verdict'
done
```
