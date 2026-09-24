"""Turns raw worker observations + fakenet flows into the report the backend consumes."""
from __future__ import annotations

import re
from typing import Any

from . import signatures

_SCHEME = re.compile(r"(?i)\b(http|https|ftp)://")
_IPV4 = re.compile(r"\b(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})\b")
_DOT = re.compile(r"\.(?=[a-z0-9-]+(?:\.[a-z]{2,}|$))", re.I)


def defang(value: str) -> str:
    """Neutralise an indicator so nothing downstream turns it into a live link.

    The report is fed to a language model, rendered in a UI, and pasted into tickets. Any
    of those may auto-link or auto-fetch a URL. Defanging is what stops the analysis
    pipeline from becoming the malware's delivery mechanism.
    """
    if not value:
        return value
    out = _SCHEME.sub(lambda m: m.group(1).replace("t", "x", 2) + "://", value)
    # Break the URL host first, so an IP-literal host is not defanged twice by _IPV4 below.
    out = re.sub(
        r"(?i)\b(h[xt]{2}ps?|f[xt]p)://([^/\s:]+)",
        lambda m: f"{m.group(1)}://{m.group(2).replace('.', '[.]')}",
        out,
    )
    out = _IPV4.sub(lambda m: "[.]".join(m.groups()), out)
    return out


def defang_host(host: str) -> str:
    if not host:
        return host
    if _IPV4.fullmatch(host):
        return host.replace(".", "[.]")
    parts = host.rsplit(".", 1)
    return f"{parts[0]}[.]{parts[1]}" if len(parts) == 2 else host


def _infra_ips(engine_meta: dict) -> set[str]:
    """Addresses that belong to the sandbox itself, not to the sample's intentions.

    Docker's embedded resolver (127.0.0.11), the fakenet sink, and the worker's own address
    are all environment artifacts. Reporting them as indicators would mislead the model and
    anyone reading the ticket, so they are stripped from the sample-facing output.
    """
    infra = {"127.0.0.11", "0.0.0.0"}
    for key in ("dns", "worker_ip"):
        value = engine_meta.get(key)
        if value:
            infra.add(value)
    return infra


def _is_infra_ip(ip: str, infra: set[str]) -> bool:
    if ip in infra:
        return True
    # Loopback and the private detonation subnet are never real destinations.
    return ip.startswith("127.") or ip.startswith("172.31.240.")


def _merge_iocs(*sources: dict | None) -> dict[str, list[str]]:
    merged: dict[str, list[str]] = {"urls": [], "domains": [], "ips": [], "emails": []}
    for source in sources:
        if not isinstance(source, dict):
            continue
        for key in merged:
            for value in source.get(key, []) or []:
                if value and value not in merged[key]:
                    merged[key].append(value)
    return {k: v[:150] for k, v in merged.items()}


def collect_iocs(observations: dict, network: dict) -> dict[str, list[str]]:
    static = observations.get("static") or {}
    dynamic = observations.get("dynamic") or {}

    sources = [
        static.get("file_iocs"),
        (static.get("vba") or {}).get("raw_iocs"),
        dynamic.get("stdout_iocs"),
    ]
    merged = _merge_iocs(*sources)

    for url in (dynamic.get("extracted_urls") or []):
        if url not in merged["urls"]:
            merged["urls"].append(url)
    for url in ((static.get("ole_objects") or {}).get("found_urls") or []):
        if url not in merged["urls"]:
            merged["urls"].append(url)

    # Anything the sample actually reached for at runtime outranks anything we merely
    # found in its bytes, so record those explicitly too.
    for query in network.get("dns_queries", []):
        name = query.get("qname")
        if name and name not in merged["domains"]:
            merged["domains"].append(name)
    for session in network.get("tcp_sessions", []) + network.get("connect_attempts", []):
        ip = session.get("ip")
        if ip and ip not in merged["ips"]:
            merged["ips"].append(ip)

    return merged


def build_llm_summary(report: dict) -> str:
    """A compact prose brief, safe to paste straight into the GPT-4o prompt.

    Written as evidence, not as a conclusion, and with every indicator defanged. The
    calling model should be able to disagree with our verdict from the same facts.
    """
    file_info = report.get("file") or {}
    verdict = report.get("verdict") or {}
    sigs = report.get("signatures") or []
    net = report.get("network") or {}
    dyn = report.get("dynamic") or {}
    iocs = report.get("iocs") or {}

    lines: list[str] = []

    lines.append(
        f"SANDBOX REPORT for attachment {file_info.get('name', '?')!r} "
        f"({file_info.get('size', 0)} bytes, SHA256 {file_info.get('sha256', '?')})."
    )
    lines.append(
        f"Identified as: {file_info.get('label', 'unknown')}. "
        f"Sandbox verdict: {verdict.get('level', 'unknown').upper()} "
        f"(score {verdict.get('score', 0)}/100, confidence {verdict.get('confidence', 0)})."
    )

    if file_info.get("extension_mismatch"):
        lines.append(f"TYPE MISMATCH: {file_info['extension_mismatch']}.")
    for flag in file_info.get("filename_flags") or []:
        lines.append(f"FILENAME: {flag}.")

    if sigs:
        lines.append("")
        lines.append("Detections, strongest first:")
        for sig in sigs[:12]:
            if sig["id"] == "RULE_ERROR":
                continue
            lines.append(f"- [{sig['severity']}] {sig['name']}: {sig['description']}")
            for item in (sig.get("evidence") or [])[:4]:
                lines.append(f"    evidence: {defang(str(item))[:300]}")
    else:
        lines.append("")
        lines.append("No detection signatures fired.")

    executed = dyn.get("executed")
    lines.append("")
    if executed:
        lines.append(
            f"DYNAMIC ANALYSIS: the sample was executed ({dyn.get('engine')}) for "
            f"{dyn.get('duration_seconds', '?')}s"
            + (" and was still running when the budget expired." if dyn.get("timed_out")
               else f" and exited with code {dyn.get('exit_code')}.")
        )
        procs = dyn.get("processes") or []
        if procs:
            lines.append(f"It spawned {dyn.get('process_count', len(procs))} process(es):")
            for proc in procs[:6]:
                lines.append(f"    {defang(proc.get('command', ''))[:250]}")
        written = dyn.get("files_written") or []
        if written:
            lines.append(f"It wrote {len(written)} file(s), including: "
                         + ", ".join(written[:6]))
        persist = dyn.get("persistence_paths") or []
        for entry in persist[:5]:
            lines.append(f"PERSISTENCE: wrote {entry['path']} ({entry['meaning']}).")
    else:
        lines.append(f"DYNAMIC ANALYSIS: not executed. Reason: "
                     f"{dyn.get('reason') or dyn.get('error') or 'unknown'}")

    dns = net.get("dns_queries") or []
    http = net.get("http_requests") or []
    connects = net.get("connect_attempts") or []
    if dns or http or connects:
        lines.append("")
        lines.append("NETWORK (simulated internet -- nothing left this machine):")
        for query in dns[:8]:
            lines.append(f"    DNS lookup: {defang_host(query.get('qname', ''))}")
        for req in http[:8]:
            url = (f"{req.get('scheme', 'http')}://{req.get('host', '')}"
                   f"{req.get('path', '')}")
            lines.append(
                f"    {req.get('method', '?')} {defang(url)}"
                + (f"  [{req.get('body_len')} byte body]" if req.get("body_len") else "")
            )
        for attempt in connects[:8]:
            lines.append(f"    TCP connect to {defang_host(attempt.get('ip', ''))}:"
                         f"{attempt.get('port')}")

    flat = [
        ("URL", iocs.get("urls", [])),
        ("domain", iocs.get("domains", [])),
        ("IP", iocs.get("ips", [])),
    ]
    shown = [(kind, values) for kind, values in flat if values]
    if shown:
        lines.append("")
        lines.append("Indicators found in the sample (defanged):")
        for kind, values in shown:
            for value in values[:10]:
                lines.append(f"    {kind}: {defang(value)}")

    errors = report.get("errors") or []
    if errors:
        lines.append("")
        lines.append("Analysis gaps -- treat conclusions about these areas as incomplete:")
        for err in errors[:5]:
            lines.append(f"    {err.get('stage', '?')}: {err.get('error', '')[:200]}")

    return "\n".join(lines)


def build(job_id: str, status: str, created_at: str, finished_at: str | None,
          duration: float | None, observations: dict | None, network: dict,
          engine_meta: dict) -> dict:
    """Assemble the final report. Never raises on partial input."""
    obs = (observations or {}).get("observations") or {}
    file_info = obs.get("file") or {}
    dynamic = obs.get("dynamic") or {}

    # strace's connect() records are the raw-IP half of network visibility; fakenet
    # covers the DNS half. Merge them, then strip the sandbox's own plumbing so only the
    # sample's intended destinations remain.
    network = dict(network)
    infra = _infra_ips(engine_meta)

    connects = []
    seen_connect = set()
    for c in (dynamic.get("tcp_connects") or []):
        ip = c.get("ip", "")
        if _is_infra_ip(ip, infra):
            continue
        key = (ip, c.get("port"))
        if key in seen_connect:
            continue
        seen_connect.add(key)
        connects.append(c)
    network["connect_attempts"] = connects[:120]

    # Collapse repeated identical DNS lookups (a resolver retries A then AAAA then again)
    # into one entry per name so the summary is not four lines of the same host.
    deduped_dns = []
    seen_dns = set()
    for q in network.get("dns_queries", []):
        name = q.get("qname", "")
        if name in seen_dns:
            continue
        seen_dns.add(name)
        deduped_dns.append(q)
    network["dns_queries"] = deduped_dns
    network["contacted_hosts"] = sorted(
        h for h in network.get("contacted_hosts", []) if h)

    scoring_input = {
        "file": file_info,
        "static": obs.get("static") or {},
        "dynamic": dynamic,
        "network": network,
        "iocs": {},
    }
    iocs = collect_iocs(obs, network)
    iocs["ips"] = [ip for ip in iocs.get("ips", []) if not _is_infra_ip(ip, infra)]
    scoring_input["iocs"] = iocs

    fired = signatures.evaluate(scoring_input)
    value, level, confidence = signatures.score(fired)

    top_reasons = [s["name"] for s in fired if s["id"] != "RULE_ERROR"][:5]
    if level == "malicious":
        summary = ("Behaviour and structure consistent with a malicious attachment.")
    elif level == "suspicious":
        summary = ("Several traits that legitimate attachments do not normally have. "
                   "Worth analyst review before delivery.")
    else:
        summary = ("Nothing characteristic of a malicious attachment was observed.")
    if status in ("failed", "timeout"):
        summary = (f"Analysis did not complete ({status}); this verdict is based on "
                   f"partial evidence and should not be treated as a clean result.")
        confidence = min(confidence, 0.4)

    report: dict[str, Any] = {
        "schema_version": "1.0",
        "job_id": job_id,
        "status": status,
        "created_at": created_at,
        "finished_at": finished_at,
        "duration_seconds": duration,
        "file": {
            "name": file_info.get("name", ""),
            "size": file_info.get("size", 0),
            "family": file_info.get("family", "unknown"),
            "label": file_info.get("label", "unknown"),
            "md5": file_info.get("md5", ""),
            "sha1": file_info.get("sha1", ""),
            "sha256": file_info.get("sha256", ""),
            "entropy": file_info.get("entropy", 0.0),
            "extension": file_info.get("extension", ""),
            "extension_mismatch": file_info.get("extension_mismatch"),
            "filename_flags": file_info.get("filename_flags", []),
        } if file_info else None,
        "verdict": {
            "score": value,
            "level": level,
            "confidence": confidence,
            "summary": summary,
            "top_reasons": top_reasons,
        },
        "signatures": fired,
        "iocs": scoring_input["iocs"],
        "network": network,
        "static": obs.get("static") or {},
        "dynamic": dynamic,
        "errors": obs.get("errors") or [],
        "engine": {
            **engine_meta,
            "timings": obs.get("timings") or {},
            "detonation_enabled": (observations or {}).get("detonation_enabled"),
        },
    }
    report["llm_summary"] = build_llm_summary(report)
    return report
