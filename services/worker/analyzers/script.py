"""Script droppers: js, vbs, wsf, hta, ps1, bat, sh, py.

Two engines, chosen by what the script is:

  box-js   -- for Windows script host content (js/jse/vbs/wsf/hta). It emulates WScript,
              ActiveXObject, XMLHTTP and friends, so the dropper resolves its real URL and
              drops its real stage 2 without a Windows machine existing. This is the right
              tool: running a .js dropper under node would do nothing useful, because node
              has no WScript.
  strace   -- for anything Linux can genuinely execute (sh, python). Real execution,
              real behaviour, contained.

PowerShell and batch are deobfuscated statically -- there is no honest way to execute them
here, and the report says so rather than pretending otherwise.
"""
from __future__ import annotations

import base64
import binascii
import json
import os
import re
import shutil

from . import behavior, common

BOXJS_FAMILIES = {"js", "jse", "vbs", "wsf", "hta"}
NATIVE_FAMILIES = {"sh", "py"}

POWERSHELL_RISK = {
    "-enc": "runs a base64-encoded command",
    "-encodedcommand": "runs a base64-encoded command",
    "-w hidden": "hides the PowerShell window",
    "-windowstyle hidden": "hides the PowerShell window",
    "-nop": "skips the user profile so no logging hooks load",
    "-noprofile": "skips the user profile so no logging hooks load",
    "-ep bypass": "bypasses the execution policy",
    "-executionpolicy bypass": "bypasses the execution policy",
    "downloadstring": "downloads and runs code from a URL in memory",
    "downloadfile": "downloads a file to disk",
    "invoke-expression": "executes a string as code",
    "iex": "executes a string as code",
    "invoke-webrequest": "makes an HTTP request",
    "start-bitstransfer": "downloads over BITS to evade proxy logging",
    "frombase64string": "decodes a base64 payload",
    "system.reflection.assembly": "loads a .NET assembly in memory",
    "[reflection.assembly]::load": "loads a .NET assembly in memory",
    "add-mppreference": "adds a Defender exclusion",
    "set-mppreference": "weakens Defender settings",
    "new-object net.webclient": "creates a downloader",
    "gzipstream": "decompresses an in-memory payload",
    "virtualalloc": "allocates executable memory for shellcode",
    "-join": "reassembles a split string to defeat scanning",
}


def _decode_b64_blobs(text: str, limit: int = 25) -> list[dict]:
    """Decode long base64 runs. UTF-16LE is tried too -- that is how -EncodedCommand looks."""
    out: list[dict] = []
    for match in common.BASE64_RE.finditer(text.encode("utf-8", "replace")):
        if len(out) >= limit:
            break
        blob = match.group(1)
        try:
            decoded = base64.b64decode(blob + b"=" * (-len(blob) % 4), validate=False)
        except (binascii.Error, ValueError):
            continue
        if len(decoded) < 8:
            continue
        as_utf16 = decoded.decode("utf-16-le", "replace")
        as_utf8 = decoded.decode("utf-8", "replace")
        # Whichever decoding yields more printable text is the intended one.
        best, encoding = (
            (as_utf16, "utf-16-le")
            if sum(c.isprintable() for c in as_utf16) > sum(c.isprintable() for c in as_utf8)
            else (as_utf8, "utf-8")
        )
        printable_ratio = sum(c.isprintable() or c in "\r\n\t" for c in best) / max(len(best), 1)
        out.append({
            "encoded_length": len(blob),
            "encoding": encoding,
            "looks_like_text": printable_ratio > 0.85,
            "looks_like_pe": decoded[:2] == b"MZ",
            "entropy": common.entropy(decoded),
            "decoded_preview": common.truncate(best if printable_ratio > 0.5
                                               else decoded[:512].hex(), 3000),
        })
    return out


def _deobfuscate(text: str) -> dict:
    """Reconstruct what the script builds at runtime, without executing it."""
    result: dict = {"fromcharcode": [], "hex_escapes": [], "reversed": [], "concatenated": []}

    for match in re.finditer(r"(?:String\.)?fromCharCode\s*\(([\d\s,]+)\)", text, re.I):
        try:
            rebuilt = "".join(chr(int(n)) for n in re.findall(r"\d+", match.group(1))
                              if int(n) < 0x110000)
        except (ValueError, OverflowError):
            continue
        if len(rebuilt) >= 4:
            result["fromcharcode"].append(rebuilt)

    for match in re.finditer(r'"((?:\\x[0-9a-fA-F]{2}){4,})"', text):
        try:
            result["hex_escapes"].append(
                bytes.fromhex(match.group(1).replace("\\x", "")).decode("utf-8", "replace"))
        except ValueError:
            continue

    for match in re.finditer(r'"([^"\n]{6,})"\s*\.\s*split\(\s*""\s*\)\s*\.\s*reverse', text, re.I):
        result["reversed"].append(match.group(1)[::-1])

    for match in re.finditer(r'(?:"[^"\n]{0,60}"\s*\+\s*){1,}"[^"\n]{0,60}"', text):
        joined = "".join(re.findall(r'"([^"\n]*)"', match.group(0)))
        if len(joined) >= 6:
            result["concatenated"].append(joined)

    for key in result:
        result[key] = common._dedupe(result[key], 40)
    return result


def _run_boxjs(path: str, workdir: str, artifact_dir: str, budget: int) -> dict:
    """Emulate a Windows script host dropper and collect what it tried to do."""
    if not shutil.which("box-js"):
        return {"executed": False, "engine": "box-js",
                "error": "box-js is not installed in this image"}

    outdir = os.path.join(workdir, "boxjs")
    os.makedirs(outdir, exist_ok=True)
    result = common.run(
        ["box-js", path, "--output-dir", outdir, "--no-kill", "--loglevel", "warn",
         "--timeout", str(max(budget - 5, 5)), "--no-echo", "--no-rewrite"],
        timeout=budget, cwd=workdir,
    )

    report: dict = {
        "executed": True,
        "engine": "box-js",
        "timed_out": result["timed_out"],
        "stdout": common.truncate(result["stdout"] + result["stderr"], 6000),
        "urls": [], "resources": [], "iocs": [], "snippets": [], "artifacts": [],
    }

    # box-js writes its findings into <sample>.results/ next to the output dir.
    results_dir = None
    for candidate in os.listdir(outdir) if os.path.isdir(outdir) else []:
        full = os.path.join(outdir, candidate)
        if os.path.isdir(full) and candidate.endswith(".results"):
            results_dir = full
            break
    if results_dir is None and os.path.isdir(outdir):
        results_dir = outdir

    if results_dir:
        for name in sorted(os.listdir(results_dir)):
            full = os.path.join(results_dir, name)
            if not os.path.isfile(full):
                continue
            try:
                size = os.path.getsize(full)
            except OSError:
                continue
            report["artifacts"].append({"name": name, "size": size})

            if name == "urls.json":
                try:
                    report["urls"] = json.load(open(full))
                except Exception:
                    pass
            elif name == "IOC.json":
                try:
                    report["iocs"] = json.load(open(full))
                except Exception:
                    pass
            elif name in ("snippets.json", "active_urls.json"):
                try:
                    data = json.load(open(full))
                    report["snippets" if name == "snippets.json" else "urls"] = data
                except Exception:
                    pass
            elif name.startswith("resource"):
                # A dropped stage 2 -- copy it out so the operator can look at it.
                dest = os.path.join(artifact_dir, f"boxjs-{name}")
                try:
                    shutil.copy2(full, dest)
                    with open(full, "rb") as fh:
                        blob = fh.read(1024 * 1024)
                    report["resources"].append({
                        "name": name, "size": size,
                        "entropy": common.entropy(blob),
                        "looks_like_pe": blob[:2] == b"MZ",
                        "sha256": common.hashes(full)["sha256"],
                    })
                except OSError:
                    pass

    # Normalise box-js's IOC structure into flat indicator lists.
    flat_urls: list[str] = []
    for item in report["iocs"] if isinstance(report["iocs"], list) else []:
        value = item.get("value") if isinstance(item, dict) else None
        if isinstance(value, dict):
            for key in ("url", "src", "file"):
                if isinstance(value.get(key), str):
                    flat_urls.append(value[key])
    for item in report["urls"] if isinstance(report["urls"], list) else []:
        if isinstance(item, str):
            flat_urls.append(item)
    report["extracted_urls"] = common._dedupe(flat_urls, 60)
    return report


def analyze(path: str, tri: dict, workdir: str, artifact_dir: str,
            budget: int, detonate: bool = True) -> dict:
    family = tri["family"]
    with open(path, "rb") as fh:
        raw = fh.read(8 * 1024 * 1024)
    text = raw.decode("utf-8", "replace")

    report: dict = {"engine": "script", "language": family}
    report["length"] = len(text)
    report["line_count"] = text.count("\n") + 1
    longest = max((len(line) for line in text.splitlines()), default=0)
    report["longest_line"] = longest
    # One enormous line is the signature of a minified/obfuscated dropper.
    report["single_line_obfuscation"] = longest > 1000
    report["entropy"] = common.entropy(raw)
    report["deobfuscated"] = _deobfuscate(text)
    report["base64_blobs"] = _decode_b64_blobs(text)
    report["source"] = common.truncate(text, 12000)

    if family in ("ps1", "bat"):
        lowered = text.lower()
        report["powershell_indicators"] = [
            {"flag": flag, "meaning": why}
            for flag, why in POWERSHELL_RISK.items() if flag in lowered
        ]

    # IOCs from the literal source plus everything deobfuscation reconstructed.
    reconstructed = "\n".join(
        v for values in report["deobfuscated"].values() for v in values
    ) + "\n" + "\n".join(
        b["decoded_preview"] for b in report["base64_blobs"] if b["looks_like_text"]
    )
    iocs = common.extract_iocs(raw)
    for key, values in common.extract_iocs(reconstructed.encode("utf-8", "replace")).items():
        for value in values:
            if value not in iocs[key]:
                iocs[key].append(value)
    report["file_iocs"] = iocs

    if not detonate:
        report["dynamic"] = {"executed": False, "reason": "detonation disabled for this job"}
        return report

    if family in BOXJS_FAMILIES:
        report["dynamic"] = _run_boxjs(path, workdir, artifact_dir, budget)
    elif family in NATIVE_FAMILIES:
        interpreter = {"sh": ["/bin/sh"], "py": ["/usr/local/bin/python3"]}[family]
        report["dynamic"] = behavior.execute(
            interpreter + [path], workdir, artifact_dir, budget, label=family)
    elif family in ("ps1", "bat"):
        report["dynamic"] = {
            "executed": False,
            "engine": "static-only",
            "reason": f"{family} needs a Windows host to execute meaningfully; this image "
                      f"deobfuscates and extracts indicators statically instead of "
                      f"pretending to detonate it",
        }
    else:
        report["dynamic"] = {"executed": False, "engine": "static-only",
                             "reason": f"no execution engine for family '{family}'"}
    return report
