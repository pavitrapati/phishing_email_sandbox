"""Office documents: OLE2 (.doc/.xls) and OOXML (.docx/.xlsm/...).

Covers the four ways an Office attachment actually gets code running today:
  1. VBA macros (olevba) -- still the volume leader
  2. Excel 4.0 / XLM macros, which sit in sheets rather than a VBA project
  3. DDE / DDEAUTO field codes, which need no macro at all
  4. Remote template injection: a benign-looking .docx whose relationships point at an
     attacker-hosted .dotm that carries the payload
Plus embedded OLE objects, which is how packagers smuggle an .exe inside a .doc.
"""
from __future__ import annotations

import os
import re
import zipfile

from . import common

AUTO_EXEC = [
    "autoopen", "auto_open", "autoclose", "auto_close", "autoexec", "auto_exec",
    "autonew", "document_open", "document_close", "documentopen", "workbook_open",
    "workbook_activate", "workbook_beforeclose", "app_workbookopen", "auto_activate",
]
SUSPICIOUS_VBA = {
    "shell": "spawns a process",
    "wscript.shell": "instantiates the Windows Script Host shell",
    "createobject": "creates a COM object at runtime",
    "getobject": "binds to a COM object, often WMI",
    "powershell": "invokes PowerShell",
    "cmd.exe": "invokes the command interpreter",
    "winmgmts": "uses WMI, commonly Win32_Process.Create",
    "xmlhttp": "makes an HTTP request",
    "winhttprequest": "makes an HTTP request",
    "urldownloadtofile": "downloads a file from a URL",
    "adodb.stream": "writes downloaded bytes to disk",
    "savetofile": "writes a file to disk",
    "environ": "reads environment variables to locate a drop path",
    "chr(": "builds strings character-by-character to defeat string scanning",
    "chrw(": "builds strings character-by-character to defeat string scanning",
    "strreverse": "reverses strings to hide them",
    "base64": "decodes base64",
    "frombase64string": "decodes base64",
    "vbnormalnofocus": "launches a process with a hidden window",
    "windowstyle": "controls process window visibility, usually to hide it",
    "declare": "declares a Win32 API import from VBA",
    "virtualalloc": "allocates executable memory (shellcode injection)",
    "createthread": "starts a thread (shellcode injection)",
    "regwrite": "writes to the registry, often for persistence",
    "schtasks": "creates a scheduled task for persistence",
    "attributes.dll": "side-loads a DLL",
    "application.run": "dispatches to another macro at runtime",
    ".spawninstance_": "uses WMI to create a process",
    "mshta": "runs remote HTML applications",
    "regsvr32": "proxy-executes code via regsvr32",
    "rundll32": "proxy-executes code via rundll32",
    "certutil": "abuses certutil to download or decode payloads",
    "bitsadmin": "abuses BITS to download payloads",
}


VBA_SOURCE_MARKERS = (b"Attribute VB_", b"Sub ", b"Function ", b"Dim ", b"Private Sub",
                      b"Public Sub", b"Auto_Open", b"Workbook_Open", b"Document_Open")


def _recover_vba_source(path: str, is_ooxml: bool) -> list[dict]:
    """Recover macro source that olevba could not extract.

    Real samples deliberately corrupt the VBA `dir`/PROJECT streams so olevba's structured
    parser bails ("VBA stomping" and malformed-project evasion), while the module streams
    still hold compressed source that Office itself will happily run. This walks the OLE
    streams directly and MS-OVBA-decompresses each one, trying a handful of candidate
    offsets because real module source begins at MODULEOFFSET, not at byte 0. Anything that
    decodes to something carrying VBA source markers is reported as a recovered module.

    It only runs as a fallback, so a well-formed document that olevba already handled is
    never touched by it.
    """
    try:
        import olefile
        from oletools.olevba import decompress_stream
    except Exception:
        return []

    def scan_ole(ole) -> list[dict]:
        recovered: list[dict] = []
        for entry in ole.listdir(streams=True, storages=False):
            name = "/".join(entry)
            try:
                raw = ole.openstream(entry).read()
            except Exception:
                continue
            # Try decompressing from byte 0 and from each MS-OVBA container signature (0x01)
            # in the first 4 KiB -- that covers the MODULEOFFSET indirection cheaply.
            offsets = [0] + [i for i, b in enumerate(raw[:4096]) if b == 0x01][:8]
            for off in offsets:
                try:
                    decoded = decompress_stream(bytearray(raw[off:]))
                except Exception:
                    continue
                if any(m in decoded for m in VBA_SOURCE_MARKERS):
                    text = decoded.split(b"\x00", 1)[0].decode("latin-1", "replace")
                    recovered.append({
                        "stream": name,
                        "name": "(recovered)",
                        "lines": text.count("\n") + 1,
                        "code": common.truncate(text, 8000),
                        "recovered": True,
                        "offset": off,
                    })
                    break
        return recovered

    try:
        if is_ooxml:
            import io
            import zipfile
            with zipfile.ZipFile(path) as zf:
                bins = [n for n in zf.namelist() if n.lower().endswith("vbaproject.bin")]
                out: list[dict] = []
                for name in bins:
                    with olefile.OleFileIO(io.BytesIO(zf.read(name))) as ole:
                        out.extend(scan_ole(ole))
                return out
        with olefile.OleFileIO(path) as ole:
            return scan_ole(ole)
    except Exception:
        return []


def _analyze_vba(path: str) -> dict:
    """Run olevba and turn its report into structured observations."""
    result = common.run(["olevba", "--json", path], timeout=90)
    out: dict = {"available": True, "macros": [], "olevba_error": None, "raw_iocs": {}}

    if result["stderr"] and "not found" in result["stderr"]:
        return {"available": False, "macros": [], "olevba_error": result["stderr"], "raw_iocs": {}}

    # olevba --json emits a JSON array, but prints warnings around it on some builds,
    # so parse defensively and fall back to the text report.
    import json as _json
    parsed = None
    text = result["stdout"]
    start = text.find("[")
    if start != -1:
        try:
            parsed = _json.loads(text[start:])
        except Exception:
            parsed = None

    sources: list[str] = []
    if parsed:
        for entry in parsed:
            if entry.get("type") == "MacroFile":
                for macro in entry.get("macros", []) or []:
                    code = macro.get("code", "") or ""
                    sources.append(code)
                    out["macros"].append({
                        "stream": macro.get("ole_stream", ""),
                        "name": macro.get("vba_filename", ""),
                        "lines": code.count("\n") + 1 if code else 0,
                        "code": common.truncate(code, 8000),
                    })
            if entry.get("type") == "error":
                out["olevba_error"] = entry.get("error")
    else:
        # Text fallback: olevba prints macro source between the stream banners.
        out["olevba_error"] = out["olevba_error"] or (
            result["stderr"].strip()[:500] or None
        )
        sources.append(text)
        if text.strip():
            out["macros"].append({"stream": "(text report)", "name": "",
                                  "lines": text.count("\n"),
                                  "code": common.truncate(text, 8000)})

    # Fallback: olevba extracted nothing usable. Try to recover module source directly.
    if not any(part.strip() for part in sources):
        recovered = _recover_vba_source(path, is_ooxml=path.lower().endswith(
            (".docx", ".docm", ".dotm", ".xlsx", ".xlsm", ".xltm", ".pptm", ".zip")))
        if recovered:
            out["macros"] = recovered
            out["recovered_without_olevba"] = True
            sources = [m["code"] for m in recovered]

    blob = "\n".join(sources)
    lowered = blob.lower()

    out["auto_exec"] = sorted({kw for kw in AUTO_EXEC if kw in lowered})
    out["suspicious_calls"] = [
        {"keyword": kw, "meaning": why}
        for kw, why in SUSPICIOUS_VBA.items() if kw in lowered
    ]
    out["total_macro_lines"] = blob.count("\n")
    out["raw_iocs"] = common.extract_iocs(blob.encode("utf-8", "replace"))

    # Deobfuscation: pull out what the macro is *building* rather than what it literally says.
    out["deobfuscated"] = _deobfuscate_vba(blob)
    if out["deobfuscated"]:
        rebuilt = "\n".join(out["deobfuscated"]).encode("utf-8", "replace")
        merged = common.extract_iocs(rebuilt)
        for key, values in merged.items():
            existing = out["raw_iocs"].setdefault(key, [])
            existing.extend(v for v in values if v not in existing)

    return out


def _deobfuscate_vba(code: str) -> list[str]:
    """Reconstruct strings that the macro assembles at runtime.

    Handles the two obfuscations that cover most real samples: Chr()/ChrW() sequences
    concatenated with &, and StrReverse of a literal. This is not a VBA interpreter --
    it is a targeted string reconstructor, and it is honest about that.
    """
    found: list[str] = []

    for match in re.finditer(r"(?:Chr[W$]?\s*\(\s*(\d{1,7})\s*\)\s*&?\s*){3,}", code, re.I):
        chars = re.findall(r"Chr[W$]?\s*\(\s*(\d{1,7})\s*\)", match.group(0), re.I)
        try:
            rebuilt = "".join(chr(int(c)) for c in chars if int(c) < 0x110000)
        except (ValueError, OverflowError):
            continue
        if len(rebuilt) >= 4 and rebuilt.isprintable():
            found.append(rebuilt)

    for match in re.finditer(r'StrReverse\s*\(\s*"([^"]{4,})"\s*\)', code, re.I):
        found.append(match.group(1)[::-1])

    # Long literal string tables joined by & -- collapse them so URLs re-form.
    for match in re.finditer(r'(?:"[^"\n]{0,80}"\s*&\s*){1,}"[^"\n]{0,80}"', code):
        pieces = re.findall(r'"([^"\n]*)"', match.group(0))
        joined = "".join(pieces)
        if len(joined) >= 8:
            found.append(joined)

    return common._dedupe(found, 60)


def _analyze_ooxml(path: str) -> dict:
    """Look at the package itself: relationships, external targets, embedded binaries."""
    info: dict = {
        "entries": [], "external_targets": [], "remote_template": None,
        "embedded_objects": [], "has_vba_project": False, "encrypted": False,
    }
    try:
        with zipfile.ZipFile(path) as zf:
            for item in zf.infolist():
                info["entries"].append({"name": item.filename, "size": item.file_size,
                                        "compressed": item.compress_size})
                lowered = item.filename.lower()
                if lowered.endswith("vbaproject.bin"):
                    info["has_vba_project"] = True
                if "/embeddings/" in lowered or "/oleobject" in lowered:
                    info["embedded_objects"].append(item.filename)

            # External relationships are how remote-template injection works.
            for name in zf.namelist():
                if not name.lower().endswith(".rels"):
                    continue
                try:
                    xml = zf.read(name).decode("utf-8", "replace")
                except Exception:
                    continue
                for rel in re.finditer(
                    r'<Relationship\b[^>]*?Id="([^"]*)"[^>]*?Type="([^"]*)"[^>]*?'
                    r'Target="([^"]*)"[^>]*?(?:TargetMode="(\w+)")?[^>]*/?>', xml
                ):
                    _id, rtype, target, mode = rel.groups()
                    if (mode or "").lower() == "external" or target.lower().startswith(
                        ("http://", "https://", "ftp://", "file://", "\\\\", "mhtml:")
                    ):
                        entry = {"part": name, "type": rtype.rsplit("/", 1)[-1],
                                 "target": target}
                        info["external_targets"].append(entry)
                        if rtype.endswith("/attachedTemplate"):
                            info["remote_template"] = target
    except zipfile.BadZipFile as exc:
        info["error"] = f"not a readable OOXML package: {exc}"
    return info


def analyze(path: str, tri: dict) -> dict:
    """Full static pass over an Office document. Returns observations only."""
    report: dict = {"engine": "office"}

    report["vba"] = _analyze_vba(path)

    # msodde --json emits an array of message objects. A document with no DDE links yields
    # only banner/header entries; real links appear as entries after the "DDE Links:" header
    # (or typed as dde-link). Parsing the structure -- rather than grepping the raw text --
    # avoids the trap of matching the word "msodde" or the header itself. (Note: --no-color
    # is an olevba flag, not an msodde one, and passing it makes msodde error out.)
    dde = common.run(["msodde", "--json", path], timeout=60)
    dde_found = False
    dde_links: list[str] = []
    try:
        import json as _json
        start = dde["stdout"].find("[")
        entries = _json.loads(dde["stdout"][start:]) if start != -1 else []
        seen_header = False
        for entry in entries:
            etype = str(entry.get("type", "")).lower()
            msg = str(entry.get("msg", "") or entry.get("data", "")).strip()
            if etype in ("dde-link", "dde"):
                dde_found = True
                if msg:
                    dde_links.append(msg)
            elif "dde links:" in msg.lower():
                seen_header = True
            elif seen_header and msg:
                dde_found = True
                dde_links.append(msg)
    except Exception:
        dde_found = False
    report["dde"] = {
        "found": dde_found,
        "links": dde_links[:20],
        "output": common.truncate(dde["stdout"], 2000),
    }

    oleobj = common.run(["oleobj", "-l", "error", path], timeout=60)
    report["ole_objects"] = {
        "output": common.truncate(oleobj["stdout"], 2000),
        "found_urls": common.extract_iocs(oleobj["stdout"].encode())["urls"],
    }

    if tri["family"].startswith("ooxml"):
        report["package"] = _analyze_ooxml(path)

    if tri["family"] in ("ole_office", "ole"):
        meta = common.run(["olemeta", path], timeout=30)
        report["metadata"] = common.truncate(meta["stdout"], 2000)
        streams = common.run(["oledir", path], timeout=30)
        report["streams"] = common.truncate(streams["stdout"], 3000)

    # Excel 4.0 macros live in sheets, not in a VBA project -- olevba flags them, but
    # check the raw bytes too so a stripped VBA project does not hide them.
    # First attempt to decrypt the file if it uses the default password.
    import io
    try:
        import msoffcrypto
        with open(path, "rb") as fh:
            msfile = msoffcrypto.OfficeFile(fh)
            msfile.load_key(password="VelvetSweatshop")
            decrypted = io.BytesIO()
            msfile.decrypt(decrypted)
            raw = decrypted.getvalue()
    except Exception:
        # Not encrypted or missing msoffcrypto; read raw file.
        with open(path, "rb") as fh:
            raw = fh.read(8 * 1024 * 1024)

    regex_indicated = bool(
        re.search(rb"(?i)(Excel 4\.0|xlm|_xlnm\.|Macro1|EXEC\s*\(|CALL\s*\()", raw)
    ) and tri["family"] in ("ole_office", "ooxml_excel")

    # BIFF8-level detection: parse Boundsheet records for hidden macro sheets.
    biff8_sheets = _detect_xlm_biff8(raw) if tri["family"] in ("ole_office",) else []
    report["xlm_biff8_sheets"] = biff8_sheets
    report["xlm_macros_indicated"] = regex_indicated or bool(biff8_sheets)

    # Embedded-executable scan: a genuine PE inside an Office document is the OLE-package
    # "double-click the icon" trick. Find MZ headers whose PE offset lands on a PE signature.
    embedded = []
    idx = raw.find(b"MZ")
    while idx != -1 and len(embedded) < 10:
        if idx + 0x40 < len(raw):
            e_lfanew = int.from_bytes(raw[idx + 0x3C:idx + 0x40], "little")
            sig_at = idx + e_lfanew
            if 0 < e_lfanew < 0x2000 and sig_at + 4 <= len(raw) and raw[sig_at:sig_at + 4] == b"PE\x00\x00":
                embedded.append({"offset": idx,
                                 "machine_bytes": raw[sig_at + 4:sig_at + 6].hex()})
        idx = raw.find(b"MZ", idx + 2)
    report["embedded_executables"] = embedded
    report["file_iocs"] = common.extract_iocs(raw)
    return report


def _detect_xlm_biff8(raw: bytes) -> list[dict]:
    """Parse BIFF8 Boundsheet records (0x0085) to find XLM macro sheets.

    A Boundsheet record has the structure:
      - 4 bytes: BOF offset of the sheet
      - 1 byte: visibility (0x00=visible, 0x01=hidden, 0x02=very hidden)
      - 1 byte: sheet type (0x00=worksheet, 0x01=macro sheet, 0x02=chart, 0x06=VB module)
      - variable: sheet name (byte-string with length prefix)

    Hidden macro sheets (type=0x01 + visibility!=0x00) are the primary XLM evasion
    technique: the sheet is invisible in Excel's tab bar but runs on open.
    """
    sheets: list[dict] = []
    # Search for Boundsheet records within OLE stream data.
    # Record type 0x0085, followed by 2-byte record length.
    i = 0
    while i < len(raw) - 10:
        # BIFF record header: type (2 bytes LE) + length (2 bytes LE)
        rtype = int.from_bytes(raw[i:i + 2], "little")
        rlen = int.from_bytes(raw[i + 2:i + 4], "little")

        if rtype == 0x0085 and 8 <= rlen <= 300 and i + 4 + rlen <= len(raw):
            data = raw[i + 4:i + 4 + rlen]
            if len(data) >= 8:
                visibility = data[4]
                sheet_type = data[5]
                # Parse sheet name: byte 6 is the name length, byte 7 is the encoding flag
                name_len = data[6]
                encoding_flag = data[7] if len(data) > 7 else 0
                if encoding_flag == 0 and len(data) >= 8 + name_len:
                    name = data[8:8 + name_len].decode("latin-1", "replace")
                elif encoding_flag == 1 and len(data) >= 8 + name_len * 2:
                    name = data[8:8 + name_len * 2].decode("utf-16-le", "replace")
                else:
                    name = f"(sheet at offset {i})"

                visibility_label = {0: "visible", 1: "hidden", 2: "very_hidden"}.get(
                    visibility, f"unknown({visibility})")
                type_label = {0: "worksheet", 1: "xlm_macro", 2: "chart", 6: "vb_module"}.get(
                    sheet_type, f"unknown({sheet_type})")

                if sheet_type == 0x01:  # XLM macro sheet
                    sheets.append({
                        "name": name,
                        "type": type_label,
                        "visibility": visibility_label,
                        "hidden": visibility != 0,
                    })
            i += 4 + rlen
        else:
            i += 2  # scan forward (we may be outside a BIFF stream)

    return sheets


def emulate(path: str, tri: dict, static_report: dict, work_dir: str, timeout: int) -> dict:
    """Emulate macros using ViperMonkey or XLMMacroDeobfuscator."""
    report = {"executed": False, "engine": "emulation", "actions": [], "iocs": {}}
    
    # Check if XLM macros are present
    if static_report.get("xlm_macros_indicated"):
        # run xlmdeobfuscator
        res = common.run(["xlmdeobfuscator", "-f", path, "--no-indent", "--output-level", "1"], timeout=timeout)
        report["executed"] = True
        report["engine"] = "xlmdeobfuscator"
        report["output"] = common.truncate(res["stdout"], 4000)
        report["error"] = common.truncate(res["stderr"], 1000) if res["stderr"] else None
        
        if res["stdout"]:
            report["iocs"] = common.extract_iocs(res["stdout"].encode())
            
        return report

    # Check if VBA macros are present
    vba_info = static_report.get("vba", {})
    if vba_info.get("macros") or vba_info.get("auto_exec"):
        # run ViperMonkey
        res = common.run(["vmonkey", path], timeout=timeout)
        report["executed"] = True
        report["engine"] = "vipermonkey"
        report["output"] = common.truncate(res["stdout"], 8000)
        report["error"] = common.truncate(res["stderr"], 1000) if res["stderr"] else None
        
        if res["stdout"]:
            report["iocs"] = common.extract_iocs(res["stdout"].encode())

        return report
        
    report["reason"] = "No macros detected to emulate"
    return report
