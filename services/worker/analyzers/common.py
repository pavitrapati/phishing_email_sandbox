"""Shared helpers for the analyzers.

Design rule for this whole package: **analyzers observe, they never judge.**
No function here returns a score or a verdict -- that lives in the API's signature engine
so detection logic can be retuned without rebuilding this (large) image.
"""
from __future__ import annotations

import hashlib
import math
import os
import re
import subprocess
from collections import Counter
from typing import Any, Iterable

# Deliberately permissive: we would rather over-extract candidate IOCs and let the
# signature engine discard them than miss a C2 hidden in a concatenated string.
URL_RE = re.compile(rb"""(?i)\b((?:https?|ftp|file)://[!-~]{4,2048}?)(?=[\s"'<>\\)\]},;]|[^!-~]|$)""")
DOMAIN_RE = re.compile(
    rb"""(?i)\b((?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+"""
    rb"""(?:com|net|org|info|biz|io|co|ru|cn|br|uk|de|fr|nl|eu|top|xyz|site|online|shop|"""
    rb"""club|live|icu|cc|tk|ml|ga|cf|gq|pw|su|link|click|zip|mov|app|dev|me|us|ca|au|in))\b"""
)
IPV4_RE = re.compile(rb"\b((?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(?:\.(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3})\b")
EMAIL_RE = re.compile(rb"(?i)\b([a-z0-9._%+-]{1,64}@[a-z0-9.-]{1,255}\.[a-z]{2,24})\b")
BASE64_RE = re.compile(rb"(?<![A-Za-z0-9+/])([A-Za-z0-9+/]{40,}={0,2})(?![A-Za-z0-9+/])")

# Hosts that appear inside every Office file on earth. Keeping them would drown the report.
BENIGN_DOMAINS = {
    "schemas.openxmlformats.org", "schemas.microsoft.com", "www.w3.org", "purl.org",
    "schemas.xmlsoap.org", "openoffice.org", "www.openoffice.org", "sun.com",
    "docs.oasis-open.org", "ns.adobe.com", "www.adobe.com", "iso.org", "www.iso.org",
    "microsoft.com", "office.microsoft.com", "go.microsoft.com", "w3.org",
}
BENIGN_IPS = {"0.0.0.0", "127.0.0.1", "255.255.255.255", "1.1.1.1", "8.8.8.8"}


def hashes(path: str) -> dict[str, str]:
    md5, sha1, sha256 = hashlib.md5(), hashlib.sha1(), hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1024 * 1024), b""):
            md5.update(chunk)
            sha1.update(chunk)
            sha256.update(chunk)
    return {"md5": md5.hexdigest(), "sha1": sha1.hexdigest(), "sha256": sha256.hexdigest()}


def entropy(data: bytes) -> float:
    """Shannon entropy in bits/byte. >7.2 over a whole file usually means packed or encrypted."""
    if not data:
        return 0.0
    counts = Counter(data)
    length = len(data)
    return round(-sum((c / length) * math.log2(c / length) for c in counts.values()), 3)


def run(cmd: list[str], timeout: int = 30, cwd: str | None = None,
        env: dict[str, str] | None = None) -> dict[str, Any]:
    """Run a tool and capture it. Never raises -- a dead tool is a finding, not a crash."""
    try:
        proc = subprocess.run(
            cmd, capture_output=True, timeout=timeout, cwd=cwd,
            env={**os.environ, **(env or {})},
        )
        return {
            "rc": proc.returncode,
            "stdout": proc.stdout.decode("utf-8", "replace"),
            "stderr": proc.stderr.decode("utf-8", "replace"),
            "timed_out": False,
        }
    except subprocess.TimeoutExpired as exc:
        return {
            "rc": None,
            "stdout": (exc.stdout or b"").decode("utf-8", "replace"),
            "stderr": (exc.stderr or b"").decode("utf-8", "replace"),
            "timed_out": True,
        }
    except FileNotFoundError:
        return {"rc": None, "stdout": "", "stderr": f"tool not found: {cmd[0]}", "timed_out": False}
    except Exception as exc:  # pragma: no cover - defensive
        return {"rc": None, "stdout": "", "stderr": str(exc), "timed_out": False}


def _dedupe(items: Iterable[str], limit: int) -> list[str]:
    seen: dict[str, None] = {}
    for item in items:
        if item not in seen:
            seen[item] = None
        if len(seen) >= limit:
            break
    return list(seen)


def extract_iocs(data: bytes, limit: int = 200) -> dict[str, list[str]]:
    """Pull candidate indicators out of any blob (file bytes, macro source, decoded strings)."""
    urls = _dedupe((m.decode("utf-8", "replace").rstrip(".,;") for m in URL_RE.findall(data)), limit)

    domains = []
    for match in DOMAIN_RE.findall(data):
        host = match.decode("utf-8", "replace").lower()
        if host not in BENIGN_DOMAINS and not any(host.endswith("." + b) for b in BENIGN_DOMAINS):
            domains.append(host)

    ips = [ip.decode() for ip in IPV4_RE.findall(data) if ip.decode() not in BENIGN_IPS]
    emails = [e.decode("utf-8", "replace").lower() for e in EMAIL_RE.findall(data)]

    return {
        "urls": urls,
        "domains": _dedupe(domains, limit),
        "ips": _dedupe(ips, limit),
        "emails": _dedupe(emails, limit),
    }


def strings(data: bytes, min_len: int = 6, limit: int = 400) -> list[str]:
    """ASCII + UTF-16LE printable runs, the way `strings -a -el` would give them."""
    out: list[str] = []
    pattern = rb"[\x20-\x7e]{%d,}" % min_len
    out.extend(m.decode("ascii") for m in re.findall(pattern, data))
    wide = rb"(?:[\x20-\x7e]\x00){%d,}" % min_len
    out.extend(m.decode("utf-16-le", "replace") for m in re.findall(wide, data))
    return _dedupe(out, limit)


def truncate(value: str, limit: int = 4000) -> str:
    if len(value) <= limit:
        return value
    return value[:limit] + f"\n...[truncated {len(value) - limit} chars]"
