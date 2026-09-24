"""First pass: what *is* this file, really?

The declared extension is attacker-controlled, so it is treated as a claim to be checked
against the content, never as ground truth. A mismatch between the two is itself one of
the strongest phishing signals we have.
"""
from __future__ import annotations

import os
import re
import zipfile

from . import common

# (magic bytes, offset, family, label)
MAGIC = [
    (b"MZ", 0, "pe", "DOS/PE executable"),
    (b"\x7fELF", 0, "elf", "ELF executable"),
    (b"%PDF-", 0, "pdf", "PDF document"),
    (b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1", 0, "ole", "OLE2 compound document"),
    (b"PK\x03\x04", 0, "zip", "ZIP container"),
    (b"PK\x05\x06", 0, "zip", "ZIP container (empty)"),
    (b"Rar!\x1a\x07", 0, "rar", "RAR archive"),
    (b"7z\xbc\xaf\x27\x1c", 0, "7z", "7-Zip archive"),
    (b"\x1f\x8b", 0, "gzip", "gzip stream"),
    (b"BZh", 0, "bzip2", "bzip2 archive"),
    (b"\xfd7zXZ", 0, "xz", "xz archive"),
    (b"MSCF", 0, "cab", "Microsoft Cabinet"),
    (b"CD001", 0x8001, "iso", "ISO 9660 image"),
    (b"L\x00\x00\x00\x01\x14\x02\x00", 0, "lnk", "Windows shortcut (.lnk)"),
    (b"\xca\xfe\xba\xbe", 0, "class", "Java class"),
    (b"{\\rtf", 0, "rtf", "Rich Text Format"),
    (b"\x00\x01\x00\x00Standard Jet DB", 0, "mdb", "Access database"),
]

SCRIPT_EXTS = {
    ".js": "js", ".jse": "js", ".vbs": "vbs", ".vbe": "vbs", ".wsf": "wsf", ".wsh": "wsf",
    ".hta": "hta", ".ps1": "ps1", ".psm1": "ps1", ".bat": "bat", ".cmd": "bat",
    ".sh": "sh", ".py": "py", ".pl": "pl", ".rb": "rb", ".jar": "jar", ".lnk": "lnk",
}
OFFICE_EXTS = {
    ".doc", ".dot", ".docx", ".docm", ".dotm", ".xls", ".xlt", ".xlsx", ".xlsm",
    ".xltm", ".xlsb", ".ppt", ".pot", ".pptx", ".pptm", ".rtf", ".pub", ".mht", ".slk",
}
ARCHIVE_EXTS = {".zip", ".rar", ".7z", ".gz", ".bz2", ".xz", ".tar", ".tgz", ".cab",
                ".iso", ".img", ".vhd", ".ace", ".arj", ".lzh"}
PE_EXTS = {".exe", ".dll", ".scr", ".com", ".sys", ".ocx", ".cpl", ".msi", ".pif"}

# Extensions that are dangerous but commonly disguised, plus the ones users are told are safe.
DANGEROUS_EXTS = PE_EXTS | set(SCRIPT_EXTS) | {".msi", ".msp", ".reg", ".inf", ".chm", ".url"}

RLO = "‮"  # right-to-left override: "invoice‮gpj.exe" renders as "invoicexe.jpg"


def _ooxml_kind(path: str) -> tuple[str, str]:
    """Tell docx from xlsm from a plain zip by looking at what is inside the OOXML package."""
    try:
        with zipfile.ZipFile(path) as zf:
            names = set(zf.namelist())
    except Exception:
        return "zip", "ZIP container"

    if "word/document.xml" in names or any(n.startswith("word/") for n in names):
        kind = "ooxml_word"
    elif "xl/workbook.xml" in names or any(n.startswith("xl/") for n in names):
        kind = "ooxml_excel"
    elif any(n.startswith("ppt/") for n in names):
        kind = "ooxml_powerpoint"
    elif "META-INF/MANIFEST.MF" in names:
        return "jar", "Java archive"
    elif "[Content_Types].xml" in names:
        kind = "ooxml_other"
    else:
        return "zip", "ZIP container"

    has_macro = any(n.lower().endswith("vbaproject.bin") for n in names)
    label = {"ooxml_word": "Word", "ooxml_excel": "Excel",
             "ooxml_powerpoint": "PowerPoint", "ooxml_other": "Office"}[kind]
    return kind, f"OOXML {label} document" + (" with VBA project" if has_macro else "")


def _is_text(head: bytes) -> bool:
    if b"\x00" in head[:1024]:
        return False
    printable = sum(1 for b in head if 0x20 <= b < 0x7F or b in (9, 10, 13))
    return len(head) > 0 and printable / len(head) > 0.90


def _script_family_from_content(head: bytes) -> str | None:
    text = head[:4096].decode("utf-8", "replace").lower()
    if re.search(r"<script|wscript\.|activexobject|new\s+activex", text):
        return "js"
    if re.search(r"createobject\s*\(|dim\s+\w+|wscript\.shell", text):
        return "vbs"
    if re.search(r"<job\b|<package\b", text):
        return "wsf"
    if re.search(r"invoke-expression|iex\s|\$env:|-encodedcommand|new-object\s+net\.", text):
        return "ps1"
    if text.startswith("#!") and "python" in text.split("\n", 1)[0]:
        return "py"
    if text.startswith("#!"):
        return "sh"
    if re.search(r"^\s*@echo\s+off|^\s*set\s+\w+=", text, re.M):
        return "bat"
    return None


def triage(path: str, declared_name: str) -> dict:
    """Identify the file and flag any disagreement between its name and its content."""
    size = os.path.getsize(path)
    with open(path, "rb") as fh:
        head = fh.read(65536)

    family, label = "unknown", "unknown"
    for sig, off, fam, lab in MAGIC:
        if head[off : off + len(sig)] == sig:
            family, label = fam, lab
            break

    if family == "zip":
        family, label = _ooxml_kind(path)

    ext = os.path.splitext(declared_name)[1].lower()

    if family == "unknown" and _is_text(head):
        detected = _script_family_from_content(head)
        if detected:
            family, label = detected, f"{detected} script (by content)"
        elif ext in SCRIPT_EXTS:
            family, label = SCRIPT_EXTS[ext], f"{SCRIPT_EXTS[ext]} script (by extension)"
        else:
            family, label = "text", "plain text"

    # An OLE container is Word/Excel/Outlook/anything -- lean on the extension to narrow it.
    if family == "ole":
        if ext in {".msg"}:
            family, label = "msg", "Outlook message"
        elif ext in OFFICE_EXTS or ext == "":
            family, label = "ole_office", "Legacy OLE Office document"

    # Content wins over the claimed extension whenever they disagree.
    mismatch = None
    expected = {
        "pe": PE_EXTS, "elf": {".elf", ".so", ".bin", ""}, "pdf": {".pdf"},
        "ole_office": OFFICE_EXTS, "msg": {".msg"},
        "ooxml_word": {".docx", ".docm", ".dotm", ".dotx", ".doc"},
        "ooxml_excel": {".xlsx", ".xlsm", ".xltm", ".xlsb", ".xls"},
        "ooxml_powerpoint": {".pptx", ".pptm", ".ppt", ".potm"},
        "zip": ARCHIVE_EXTS, "rar": ARCHIVE_EXTS, "7z": ARCHIVE_EXTS,
        "gzip": ARCHIVE_EXTS, "cab": ARCHIVE_EXTS, "iso": ARCHIVE_EXTS,
    }.get(family)
    if expected is not None and ext and ext not in expected:
        mismatch = f"content is {label} but the filename claims '{ext}'"

    name_flags = []
    if RLO in declared_name:
        name_flags.append("filename contains a right-to-left override character, which "
                          "hides the real extension from the user")
    if re.search(r"\.(jpg|jpeg|png|gif|pdf|doc|docx|xls|xlsx|txt|mp4)\s*\.\w+$",
                 declared_name, re.I):
        name_flags.append("double extension in filename")
    if len(re.sub(r"\S", "", declared_name)) > 12 or "        " in declared_name:
        name_flags.append("long whitespace run in filename, used to push the real extension "
                          "out of view")

    return {
        "name": declared_name,
        "size": size,
        "family": family,
        "label": label,
        "extension": ext,
        "extension_mismatch": mismatch,
        "extension_is_dangerous": ext in DANGEROUS_EXTS,
        "filename_flags": name_flags,
        "entropy": common.entropy(head),
        "head_hex": head[:32].hex(),
        **common.hashes(path),
    }
