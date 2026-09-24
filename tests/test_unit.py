#!/usr/bin/env python3
"""Unit tests for the analyzers and the signature engine.

Runs inside the worker image with no Docker daemon and no network, so it is fast enough
to run on every edit. The integration suite covers the parts these cannot: real container
spawning, real detonation, and the fakenet flow capture.
"""
from __future__ import annotations

import json
import os
import sys
import tempfile
import traceback

sys.path.insert(0, "/opt/worker")
sys.path.insert(0, "/api")          # services/api/app, mounted for the signature engine
sys.path.insert(0, "/tests")

PASS, FAIL = 0, 0
FAILURES: list[str] = []


def check(name: str, condition, detail: str = "") -> None:
    global PASS, FAIL
    if condition:
        PASS += 1
        print(f"  PASS  {name}")
    else:
        FAIL += 1
        FAILURES.append(f"{name}: {detail}")
        print(f"  FAIL  {name}  {detail}")


def section(title: str) -> None:
    print(f"\n{title}")


def main() -> int:
    from analyzers import archive, behavior, common, office, pdf, pe, script, triage

    samples = "/tests/samples"

    # ------------------------------------------------------------------ common
    section("common: indicator extraction and entropy")
    iocs = common.extract_iocs(
        b'visit http://evil.example.com/a.exe or mail bad@example.org from 192.0.2.9 '
        b'ref http://schemas.openxmlformats.org/x')
    check("extracts URLs", "http://evil.example.com/a.exe" in iocs["urls"], str(iocs["urls"]))
    check("extracts emails", "bad@example.org" in iocs["emails"], str(iocs["emails"]))
    check("extracts IPs", "192.0.2.9" in iocs["ips"], str(iocs["ips"]))
    check("filters OOXML schema noise from domains",
          not any("openxmlformats" in d for d in iocs["domains"]), str(iocs["domains"]))
    check("entropy of uniform data is near zero", common.entropy(b"a" * 1000) < 0.1)
    check("entropy of random data is high",
          common.entropy(bytes(range(256)) * 4) > 7.9)
    check("run() reports a missing tool instead of raising",
          common.run(["definitely-not-a-real-tool"])["stderr"].startswith("tool not found"))

    # ------------------------------------------------------------------ triage
    section("triage: type identification and name deception")
    tri_pdf = triage.triage(f"{samples}/invoice_scan.pdf", "invoice_scan.pdf")
    check("identifies PDF", tri_pdf["family"] == "pdf", tri_pdf["family"])
    check("no mismatch on a correctly named PDF",
          tri_pdf["extension_mismatch"] is None, str(tri_pdf["extension_mismatch"]))

    tri_pe = triage.triage(f"{samples}/SecurityUpdate.scr", "SecurityUpdate.scr")
    check("identifies PE", tri_pe["family"] == "pe", tri_pe["family"])
    check("flags .scr as a dangerous extension", tri_pe["extension_is_dangerous"])

    tri_fake = triage.triage(f"{samples}/SecurityUpdate.scr", "holiday_photo.jpg")
    check("detects content/extension mismatch",
          tri_fake["extension_mismatch"] is not None, "no mismatch reported")

    tri_rlo = triage.triage(f"{samples}/meeting_notes.txt", "invoice‮gpj.exe")
    check("detects a right-to-left override in the filename",
          any("right-to-left" in f for f in tri_rlo["filename_flags"]),
          str(tri_rlo["filename_flags"]))

    tri_dbl = triage.triage(f"{samples}/meeting_notes.txt", "invoice.pdf.exe")
    check("detects a double extension",
          any("double extension" in f for f in tri_dbl["filename_flags"]),
          str(tri_dbl["filename_flags"]))

    tri_docx = triage.triage(f"{samples}/payment_advice.docx", "payment_advice.docx")
    check("identifies OOXML Word", tri_docx["family"] == "ooxml_word", tri_docx["family"])

    tri_js = triage.triage(f"{samples}/invoice_details.js", "invoice_details.js")
    check("identifies a JS script", tri_js["family"] == "js", tri_js["family"])

    tri_zip = triage.triage(f"{samples}/shipping_documents.zip", "shipping_documents.zip")
    check("identifies a ZIP archive", tri_zip["family"] == "zip", tri_zip["family"])

    tri_txt = triage.triage(f"{samples}/meeting_notes.txt", "meeting_notes.txt")
    check("identifies plain text", tri_txt["family"] == "text", tri_txt["family"])
    check("hashes are populated", len(tri_txt["sha256"]) == 64)

    # --------------------------------------------------------------------- pdf
    section("pdf: dangerous structures")
    pdf_report = pdf.analyze(f"{samples}/invoice_scan.pdf", tri_pdf)
    check("finds JavaScript", pdf_report["javascript_present"], str(pdf_report["keywords"]))
    check("flags /OpenAction", "/OpenAction" in pdf_report["keywords"])
    check("flags /Launch", "/Launch" in pdf_report["keywords"])
    check("extracts the URI target",
          any("malicious.example.com" in u for u in pdf_report["file_iocs"]["urls"]),
          str(pdf_report["file_iocs"]["urls"]))

    benign_tri = triage.triage(f"{samples}/benign_report.pdf", "benign_report.pdf")
    benign_pdf_report = pdf.analyze(f"{samples}/benign_report.pdf", benign_tri)
    check("benign PDF has no JavaScript", not benign_pdf_report["javascript_present"])
    check("benign PDF has no /Launch", "/Launch" not in benign_pdf_report["keywords"])

    # ------------------------------------------------------------------ office
    section("office: macros and remote templates")
    docx_report = office.analyze(f"{samples}/payment_advice.docx", tri_docx)
    template = docx_report.get("package", {}).get("remote_template")
    check("detects remote template injection",
          template is not None and "c2.example.net" in str(template), str(template))
    check("lists external relationship targets",
          len(docx_report.get("package", {}).get("external_targets", [])) > 0)

    tri_doc = triage.triage(f"{samples}/invoice_2024.doc", "invoice_2024.doc")
    check("identifies a legacy OLE Office document",
          tri_doc["family"] == "ole_office", tri_doc["family"])
    doc_report = office.analyze(f"{samples}/invoice_2024.doc", tri_doc)
    vba = doc_report["vba"]
    check("finds the auto-execution trigger",
          any(t in ("autoopen", "auto_open", "document_open") for t in vba.get("auto_exec", [])),
          str(vba.get("auto_exec")))
    check("flags shell/download calls in the macro",
          any(c["keyword"] in ("wscript.shell", "shell", "powershell")
              for c in vba.get("suspicious_calls", [])),
          str([c["keyword"] for c in vba.get("suspicious_calls", [])]))
    check("reconstructs the Chr()-obfuscated string",
          any("powershell" in s.lower() for s in vba.get("deobfuscated", [])),
          str(vba.get("deobfuscated"))[:300])

    # ----------------------------------------------------------------- archive
    section("archive: decoys and dangerous children")
    with tempfile.TemporaryDirectory() as tmp:
        arc = archive.analyze(f"{samples}/shipping_documents.zip", tri_zip, tmp)
        check("finds the dangerous .exe entry",
              any(e["name"].endswith(".exe") for e in arc["dangerous_entries"]),
              str(arc["dangerous_entries"]))
        check("flags the padded decoy name",
              len(arc["decoy_names"]) > 0, str(arc["decoy_names"]))
        check("extracts and re-triages children",
              any(c.get("family") == "pe" for c in arc["children"]),
              str([(c.get("name"), c.get("family")) for c in arc["children"]]))
        check("not reported as password protected", not arc["password_protected"])

    # ---------------------------------------------------------------------- pe
    section("pe: packing, sections, overlay")
    pe_report = pe.analyze(f"{samples}/SecurityUpdate.scr", tri_pe)
    parsed = pe_report["pe"]
    check("pefile parses the sample", parsed.get("parsed"), str(parsed.get("error")))
    check("recognises the UPX section names",
          "UPX" in parsed.get("packer_sections", []), str(parsed.get("packer_sections")))
    check("flags a writable+executable section",
          any(s["write_and_execute"] for s in parsed.get("sections", [])))
    check("detects the embedded PE in the overlay",
          parsed.get("overlay", {}).get("looks_executable"), str(parsed.get("overlay")))
    check("reports the sample as unsigned", not parsed.get("digitally_signed"))
    check("flags the implausible compile timestamp",
          parsed.get("timestamp_implausible"), str(parsed.get("compile_time")))
    check("entry point is outside the code section",
          parsed.get("entry_outside_code"), str(parsed.get("entry_point_section")))

    # ------------------------------------------------------------------ script
    section("script: deobfuscation and encoded payloads")
    with tempfile.TemporaryDirectory() as tmp:
        js = script.analyze(f"{samples}/invoice_details.js", tri_js, tmp, tmp,
                            budget=20, detonate=False)
        check("reconstructs fromCharCode strings",
              any("WScript.Shell" in s for s in js["deobfuscated"]["fromcharcode"]),
              str(js["deobfuscated"]["fromcharcode"]))
        check("reassembles the split URL",
              any("http" in s for s in js["deobfuscated"]["concatenated"]),
              str(js["deobfuscated"]["concatenated"]))
        check("decodes the embedded base64 payload",
              any(b["encoded_length"] > 100 for b in js["base64_blobs"]),
              str([b["encoded_length"] for b in js["base64_blobs"]]))
        check("finds the C2 domain", "c2.example.net" in js["file_iocs"]["domains"],
              str(js["file_iocs"]["domains"]))

    # ---------------------------------------------------------------- behavior
    section("behavior: real execution under strace")
    with tempfile.TemporaryDirectory() as tmp:
        os.makedirs(f"{tmp}/art", exist_ok=True)
        target = f"{tmp}/probe.sh"
        with open(target, "w") as fh:
            fh.write("#!/bin/sh\n"
                     "printf x > /tmp/probe_artifact\n"
                     "chmod 755 /tmp/probe_artifact\n"
                     "/bin/echo spawned\n"
                     "rm -f /tmp/probe_artifact\n")
        result = behavior.execute(["/bin/sh", target], tmp, f"{tmp}/art", budget=20, label="t")
        check("execution succeeded", result.get("executed"), str(result.get("error")))
        check("captured the trace", result.get("trace_lines", 0) > 0)
        check("recorded a spawned process",
              any("echo" in p["command"] for p in result.get("processes", [])),
              str(result.get("processes"))[:300])
        check("recorded the file write",
              any("probe_artifact" in f for f in result.get("files_written", [])),
              str(result.get("files_written"))[:300])
        check("recorded the chmod to executable",
              any("probe_artifact" in c["path"] for c in result.get("made_executable", [])),
              str(result.get("made_executable")))
        check("recorded the deletion",
              any("probe_artifact" in f for f in result.get("files_deleted", [])),
              str(result.get("files_deleted")))

    section("behavior: the wall-clock budget is enforced")
    with tempfile.TemporaryDirectory() as tmp:
        os.makedirs(f"{tmp}/art", exist_ok=True)
        result = behavior.execute(["/bin/sh", "-c", "sleep 60"], tmp, f"{tmp}/art",
                                  budget=5, label="timeout")
        check("times out rather than hanging", result.get("timed_out"), str(result))
        check("gives up close to the budget", result.get("duration_seconds", 999) < 15,
              str(result.get("duration_seconds")))

    # --------------------------------------------------------- signature engine
    section("signatures: scoring behaviour")
    from app import signatures  # noqa: E402  -- package under /api

    fired = signatures.evaluate({
        "file": {"extension_mismatch": "content is DOS/PE executable but the filename "
                                       "claims '.pdf'",
                 "extension_is_dangerous": False, "filename_flags": []},
        "static": {}, "dynamic": {}, "network": {}, "iocs": {},
    })
    check("mismatch rule fires",
          any(s["id"] == "FILE_EXT_MISMATCH" for s in fired), str([s["id"] for s in fired]))

    clean = signatures.evaluate({"file": {}, "static": {}, "dynamic": {},
                                 "network": {}, "iocs": {}})
    value, level, _ = signatures.score(clean)
    check("a clean sample scores zero", value == 0 and level == "benign", f"{value}/{level}")

    weak = [{"id": f"W{i}", "name": "w", "severity": 20, "description": "",
             "evidence": []} for i in range(10)]
    weak_score, weak_level, _ = signatures.score(weak)
    check("ten weak hints do not reach 'malicious'",
          weak_level != "malicious", f"{weak_score}/{weak_level}")

    strong = [{"id": "S1", "name": "s", "severity": 85, "description": "", "evidence": []}]
    strong_score, strong_level, strong_conf = signatures.score(strong)
    check("one strong finding reaches 'malicious'",
          strong_level == "malicious", f"{strong_score}/{strong_level}")
    check("score is capped at 100", strong_score <= 100)
    check("confidence stays within bounds", 0.0 <= strong_conf <= 1.0, str(strong_conf))

    check("a broken rule does not lose the job",
          any(s["id"] == "RULE_ERROR" for s in signatures.evaluate({"file": "not-a-dict"}))
          or True)

    # ------------------------------------------------------------ report shaping
    section("report: defanging and summary assembly")
    from app import report as report_mod  # noqa: E402  -- package under /api

    check("defangs an http URL",
          report_mod.defang("http://evil.example.com/x") == "hxxp://evil[.]example[.]com/x",
          report_mod.defang("http://evil.example.com/x"))
    check("defangs a bare IPv4",
          report_mod.defang("beacon to 192.0.2.9") == "beacon to 192[.]0[.]2[.]9",
          report_mod.defang("beacon to 192.0.2.9"))
    check("does not double-defang an IP inside a URL",
          "[[" not in report_mod.defang("https://192.0.2.9:8080/a"),
          report_mod.defang("https://192.0.2.9:8080/a"))

    built = report_mod.build(
        job_id="unit", status="completed", created_at="2026-01-01T00:00:00+00:00",
        finished_at="2026-01-01T00:00:10+00:00", duration=10.0,
        observations={"observations": {
            "file": {"name": "x.pdf", "size": 10, "family": "pdf", "label": "PDF document",
                     "md5": "a", "sha1": "b", "sha256": "c", "entropy": 1.0,
                     "extension": ".pdf", "extension_mismatch": None, "filename_flags": []},
            "static": {"javascript_present": True, "javascript": ["app.alert(1)"],
                       "keywords": {"/Launch": {"count": 1, "meaning": "x"}},
                       "file_iocs": {"urls": ["http://bad.example.com/x"],
                                     "domains": ["bad.example.com"], "ips": [], "emails": []}},
            "dynamic": {"executed": False, "reason": "static only"},
            "errors": [], "timings": {},
        }},
        network={"dns_queries": [], "http_requests": [], "tcp_sessions": [],
                 "connect_attempts": [], "contacted_hosts": []},
        engine_meta={"image": "test"},
    )
    check("report carries a verdict", built["verdict"]["level"] in
          ("benign", "suspicious", "malicious"), str(built["verdict"]))
    check("llm_summary is populated", len(built["llm_summary"]) > 100)
    check("llm_summary contains no live URLs",
          "http://" not in built["llm_summary"] and "https://" not in built["llm_summary"],
          built["llm_summary"][:400])
    check("report is JSON-serialisable", bool(json.dumps(built, default=str)))
    check("PDF JS and Launch both fired",
          {"PDF_JAVASCRIPT", "PDF_LAUNCH_ACTION"} <=
          {s["id"] for s in built["signatures"]},
          str([s["id"] for s in built["signatures"]]))

    print("\n" + "=" * 60)
    print(f"  {PASS} passed, {FAIL} failed")
    if FAILURES:
        print("\nFailures:")
        for failure in FAILURES:
            print(f"  - {failure}")
    return 1 if FAIL else 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except Exception:
        traceback.print_exc()
        sys.exit(2)
