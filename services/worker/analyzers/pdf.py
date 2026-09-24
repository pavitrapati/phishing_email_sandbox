"""PDF: structure walk plus extraction of anything that can execute.

A weaponised PDF almost always does one of: run embedded JavaScript on open, use a
/Launch action to start a local program, carry an embedded file for the user to click,
or just be a lure that links to a credential-harvesting page. All four are covered here.
The extracted JavaScript is handed to the script engine for emulation, not run natively.
"""
from __future__ import annotations

import re
import zlib

from . import common

# Keyword -> why it matters. Counted against both the raw bytes and the parsed object tree,
# because a keyword hidden inside a compressed object stream will not appear in raw bytes.
RISK_KEYWORDS = {
    b"/JavaScript": "document carries JavaScript",
    b"/JS": "document carries JavaScript",
    b"/OpenAction": "an action runs automatically when the document is opened",
    b"/AA": "an additional-action trigger is set (page open, field focus, ...)",
    b"/Launch": "a /Launch action can start an external program",
    b"/EmbeddedFile": "a file is embedded inside the PDF",
    b"/Filespec": "a file specification is present (embedded or external file)",
    b"/URI": "the document links out to a URL",
    b"/SubmitForm": "the document can POST form data to a remote server",
    b"/GoToR": "the document jumps into a remote document",
    b"/RichMedia": "embedded Flash/rich media, a historic exploit vector",
    b"/XFA": "XFA forms, which carry their own scriptable logic",
    b"/AcroForm": "an interactive form is present",
    b"/ObjStm": "objects are packed into compressed object streams (hides keywords)",
    b"/Encrypt": "the document is encrypted",
}


def _decompress_streams(raw: bytes, limit: int = 60) -> list[bytes]:
    """Inflate FlateDecode streams so keywords and JS inside them become visible."""
    out: list[bytes] = []
    for match in re.finditer(rb"stream\r?\n", raw):
        if len(out) >= limit:
            break
        start = match.end()
        end = raw.find(b"endstream", start)
        if end == -1:
            continue
        blob = raw[start:end].strip(b"\r\n")
        try:
            out.append(zlib.decompress(blob))
        except zlib.error:
            try:  # raw deflate without a zlib header
                out.append(zlib.decompressobj(-15).decompress(blob))
            except zlib.error:
                continue
    return out


def _walk_with_pikepdf(path: str) -> dict:
    """Parse the object tree properly. Falls back cleanly if the PDF is malformed."""
    info: dict = {"parsed": False, "pages": None, "javascript": [], "embedded_files": [],
                  "open_action": None, "launch_actions": [], "uris": [], "error": None}
    try:
        import pikepdf
    except ImportError:
        info["error"] = "pikepdf not installed"
        return info

    try:
        # Malformed PDFs are the norm for malicious ones -- do not let a parse error
        # cost us the whole analysis.
        pdf = pikepdf.open(path, suppress_warnings=True)
    except Exception as exc:
        info["error"] = f"{type(exc).__name__}: {exc}"
        return info

    with pdf:
        info["parsed"] = True
        info["pages"] = len(pdf.pages)
        try:
            info["pdf_version"] = str(pdf.pdf_version)
            info["is_encrypted"] = bool(pdf.is_encrypted)
        except Exception:
            pass

        root = pdf.Root

        if "/OpenAction" in root:
            info["open_action"] = common.truncate(repr(root.OpenAction), 1500)

        # Document-level JavaScript in the name tree.
        try:
            names = root.get("/Names", {})
            js_tree = names.get("/JavaScript", {}) if names else {}
            for entry in (js_tree.get("/Names", []) if js_tree else []):
                try:
                    obj = entry
                    if hasattr(obj, "get") and "/JS" in obj:
                        code = obj["/JS"]
                        text = bytes(code.read_bytes()).decode("utf-8", "replace") \
                            if hasattr(code, "read_bytes") else str(code)
                        info["javascript"].append(common.truncate(text, 8000))
                except Exception:
                    continue
        except Exception:
            pass

        # Embedded files -- the "open the attached invoice" trick, one layer deeper.
        try:
            names = root.get("/Names", {})
            ef = names.get("/EmbeddedFiles", {}) if names else {}
            items = list(ef.get("/Names", [])) if ef else []
            for i in range(0, len(items) - 1, 2):
                spec = items[i + 1]
                name = str(items[i])
                size = None
                try:
                    stream = spec["/EF"]["/F"]
                    data = bytes(stream.read_bytes())
                    size = len(data)
                    digest = common.entropy(data[:65536])
                except Exception:
                    digest = None
                info["embedded_files"].append(
                    {"name": name, "size": size, "entropy": digest}
                )
        except Exception:
            pass

        # Per-page and annotation actions.
        try:
            for page_no, page in enumerate(pdf.pages, 1):
                for key in ("/AA", "/OpenAction"):
                    if key in page:
                        info.setdefault("page_actions", []).append(
                            {"page": page_no, "key": key,
                             "value": common.truncate(repr(page[key]), 800)}
                        )
                for annot in (page.get("/Annots", []) or []):
                    try:
                        action = annot.get("/A")
                        if not action:
                            continue
                        subtype = str(action.get("/S", ""))
                        if subtype == "/URI":
                            info["uris"].append(str(action.get("/URI", "")))
                        elif subtype == "/Launch":
                            info["launch_actions"].append(
                                common.truncate(repr(action), 800))
                        elif subtype == "/JavaScript" and "/JS" in action:
                            js = action["/JS"]
                            text = bytes(js.read_bytes()).decode("utf-8", "replace") \
                                if hasattr(js, "read_bytes") else str(js)
                            info["javascript"].append(common.truncate(text, 8000))
                    except Exception:
                        continue
        except Exception:
            pass

    info["uris"] = common._dedupe(info["uris"], 100)
    return info


def analyze(path: str, tri: dict) -> dict:
    with open(path, "rb") as fh:
        raw = fh.read(32 * 1024 * 1024)

    report: dict = {"engine": "pdf"}
    report["structure"] = _walk_with_pikepdf(path)

    inflated = _decompress_streams(raw)
    searchable = raw + b"\n" + b"\n".join(inflated)

    report["keywords"] = {
        kw.decode(): {"count": searchable.count(kw), "meaning": why}
        for kw, why in RISK_KEYWORDS.items() if kw in searchable
    }
    report["object_streams_inflated"] = len(inflated)

    # JavaScript can also sit in a compressed stream that pikepdf did not surface.
    js_blobs = list(report["structure"].get("javascript", []))
    for blob in inflated:
        if re.search(rb"(?i)\b(eval|unescape|app\.|this\.exportDataObject|util\.print[df]|"
                     rb"String\.fromCharCode|Collab\.)", blob):
            js_blobs.append(common.truncate(blob.decode("utf-8", "replace"), 8000))
    report["javascript"] = common._dedupe(js_blobs, 20)
    report["javascript_present"] = bool(report["javascript"])

    # Incremental updates: many pages of "/Prev" chains can mean an appended payload.
    report["incremental_updates"] = max(0, raw.count(b"%%EOF") - 1)
    report["file_iocs"] = common.extract_iocs(searchable)
    for uri in report["structure"].get("uris", []):
        if uri and uri not in report["file_iocs"]["urls"]:
            report["file_iocs"]["urls"].append(uri)

    return report
