"""Archives and containers: zip, 7z, rar, tar/gz, cab, iso/img.

Archives are the dominant phishing delivery wrapper because they survive mail gateways.
The interesting facts are structural: is it password-protected (so the gateway cannot
scan it, but the email body helpfully supplies the password), does it hide a dangerous
extension, does it contain a path traversal, and what are the children?

Children are extracted and re-triaged one level deep. Depth is capped deliberately --
a zip bomb is a resource attack, and unbounded recursion is how you fall for it.
"""
from __future__ import annotations

import os
import shutil
import tarfile
import zipfile

from . import common, triage as triage_mod

MAX_CHILDREN = 60
MAX_TOTAL_UNPACKED = 512 * 1024 * 1024   # refuse to inflate more than 512 MiB
MAX_RATIO = 200                          # compression ratio above this smells like a bomb
MAX_DEPTH = 3                            # how many nested archive layers to open
NESTED_ARCHIVE_FAMILIES = {"zip", "rar", "7z", "gzip", "bzip2", "xz", "cab", "iso",
                           "jar", "ooxml_word", "ooxml_excel", "ooxml_powerpoint",
                           "ooxml_other"}


def _list_zip(path: str) -> dict:
    info: dict = {"format": "zip", "entries": [], "encrypted": False,
                  "traversal": [], "error": None}
    try:
        with zipfile.ZipFile(path) as zf:
            total_raw = total_comp = 0
            for item in zf.infolist():
                encrypted = bool(item.flag_bits & 0x1)
                info["encrypted"] |= encrypted
                total_raw += item.file_size
                total_comp += max(item.compress_size, 1)
                name = item.filename
                if name.startswith("/") or ".." in name.replace("\\", "/").split("/"):
                    info["traversal"].append(name)
                info["entries"].append({
                    "name": name,
                    "size": item.file_size,
                    "compressed": item.compress_size,
                    "encrypted": encrypted,
                    "extension": os.path.splitext(name)[1].lower(),
                    "is_dir": name.endswith("/"),
                })
            info["total_uncompressed"] = total_raw
            info["compression_ratio"] = round(total_raw / max(total_comp, 1), 1)
    except Exception as exc:
        info["error"] = f"{type(exc).__name__}: {exc}"
    return info


def _list_tar(path: str) -> dict:
    info: dict = {"format": "tar", "entries": [], "encrypted": False,
                  "traversal": [], "error": None}
    try:
        with tarfile.open(path) as tf:
            total = 0
            for member in tf.getmembers():
                total += member.size
                if member.name.startswith("/") or ".." in member.name.split("/"):
                    info["traversal"].append(member.name)
                info["entries"].append({
                    "name": member.name, "size": member.size,
                    "extension": os.path.splitext(member.name)[1].lower(),
                    "is_dir": member.isdir(),
                    "is_link": member.issym() or member.islnk(),
                })
            info["total_uncompressed"] = total
    except Exception as exc:
        info["error"] = f"{type(exc).__name__}: {exc}"
    return info


def _list_via_7z(path: str) -> dict:
    """7z reads rar, 7z, cab, iso and more. Parse its listing rather than guessing formats."""
    info: dict = {"format": "7z-supported", "entries": [], "encrypted": False,
                  "traversal": [], "error": None}
    result = common.run(["7z", "l", "-slt", "-p", path], timeout=60)
    if result["rc"] not in (0, 1, 2):
        info["error"] = (result["stderr"] or result["stdout"])[:500]
    text = result["stdout"]
    if "Wrong password" in text or "Enter password" in text or "wrong password" in text.lower():
        info["encrypted"] = True

    current: dict = {}
    for line in text.splitlines():
        if line.startswith("Path = ") and current:
            info["entries"].append(current)
            current = {}
        if " = " not in line:
            continue
        key, _, value = line.partition(" = ")
        key = key.strip()
        if key == "Path":
            current = {"name": value, "extension": os.path.splitext(value)[1].lower()}
            if value.startswith("/") or ".." in value.replace("\\", "/").split("/"):
                info["traversal"].append(value)
        elif key == "Size" and value.isdigit():
            current["size"] = int(value)
        elif key == "Encrypted":
            enc = value.strip() == "+"
            current["encrypted"] = enc
            info["encrypted"] |= enc
        elif key == "Attributes":
            current["is_dir"] = "D" in value
    if current:
        info["entries"].append(current)
    # The first "Path" is the archive itself in -slt output; drop it.
    if info["entries"] and info["entries"][0].get("name", "").endswith(os.path.basename(path)):
        info["entries"] = info["entries"][1:]
    info["total_uncompressed"] = sum(e.get("size", 0) for e in info["entries"])
    return info


def _extract(path: str, family: str, dest: str) -> dict:
    """Unpack one level. Refuses to inflate past MAX_TOTAL_UNPACKED (zip-bomb guard)."""
    os.makedirs(dest, exist_ok=True)
    if family in ("zip", "ooxml_word", "ooxml_excel", "ooxml_powerpoint", "ooxml_other", "jar"):
        result = common.run(["7z", "x", "-y", "-p", f"-o{dest}", path], timeout=120)
    elif family in ("rar", "7z", "cab", "iso"):
        result = common.run(["7z", "x", "-y", "-p", f"-o{dest}", path], timeout=120)
    elif family in ("gzip", "bzip2", "xz"):
        result = common.run(["7z", "x", "-y", "-p", f"-o{dest}", path], timeout=120)
    else:
        try:
            with tarfile.open(path) as tf:
                tf.extractall(dest, filter="data")  # filter blocks traversal + device files
            result = {"rc": 0, "stdout": "", "stderr": "", "timed_out": False}
        except Exception as exc:
            result = {"rc": 1, "stdout": "", "stderr": str(exc), "timed_out": False}

    total = 0
    for root, _dirs, files in os.walk(dest):
        for name in files:
            try:
                total += os.path.getsize(os.path.join(root, name))
            except OSError:
                continue
    if total > MAX_TOTAL_UNPACKED:
        shutil.rmtree(dest, ignore_errors=True)
        return {"ok": False, "reason": f"unpacked size {total} exceeds the "
                                       f"{MAX_TOTAL_UNPACKED} byte limit (possible zip bomb)",
                "bytes": total}
    return {"ok": result["rc"] == 0 or total > 0, "stderr": result["stderr"][:400],
            "bytes": total}


def analyze(path: str, tri: dict, workdir: str) -> dict:
    family = tri["family"]
    report: dict = {"engine": "archive"}

    if family == "zip" or family.startswith("ooxml") or family == "jar":
        listing = _list_zip(path)
    elif family in ("gzip", "bzip2", "xz") and path.endswith((".tar.gz", ".tgz", ".tar.bz2", ".tar.xz")):
        listing = _list_tar(path)
    else:
        listing = _list_via_7z(path)

    report["listing"] = {k: v for k, v in listing.items() if k != "entries"}
    report["listing"]["entry_count"] = len(listing.get("entries", []))
    report["entries"] = listing.get("entries", [])[:MAX_CHILDREN]

    dangerous = [
        e for e in listing.get("entries", [])
        if e.get("extension") in triage_mod.DANGEROUS_EXTS and not e.get("is_dir")
    ]
    report["dangerous_entries"] = dangerous[:MAX_CHILDREN]
    report["zip_bomb_suspected"] = listing.get("compression_ratio", 0) > MAX_RATIO
    report["password_protected"] = bool(listing.get("encrypted"))
    report["path_traversal"] = listing.get("traversal", [])[:20]

    # Only decoy names matter here; a real .exe named .exe is caught by dangerous_entries.
    decoys = []
    for entry in listing.get("entries", []):
        name = entry.get("name", "")
        if triage_mod.RLO in name:
            decoys.append({"name": name, "reason": "right-to-left override in name"})
        elif entry.get("extension") in triage_mod.DANGEROUS_EXTS and name.count(".") >= 2:
            decoys.append({"name": name, "reason": "double extension"})
    report["decoy_names"] = decoys[:20]

    # Extract and re-triage children. Nested archives (zip-in-zip is a mainstream evasion)
    # are opened too, up to MAX_DEPTH, so a PE buried a few layers down is still found.
    children: list[dict] = []
    if not report["password_protected"]:
        dest = os.path.join(workdir, "unpacked")
        extraction = _extract(path, family, dest)
        report["extraction"] = extraction
        if extraction.get("ok"):
            _collect_children(dest, workdir, children, depth=1, prefix="")
    else:
        report["extraction"] = {
            "ok": False,
            "reason": "archive is password-protected; contents cannot be inspected. "
                      "This is itself a strong phishing signal -- the password is normally "
                      "supplied in the email body specifically to defeat gateway scanning.",
        }

    report["children"] = children[:MAX_CHILDREN * MAX_DEPTH]
    report["max_child_depth"] = max((c.get("depth", 1) for c in children), default=0)
    # A single flag the scoring engine can read: any executable content anywhere inside,
    # at any nesting depth. This is what closes the nested-archive blind spot.
    report["contains_executable"] = any(
        c.get("family") in ("pe", "elf") or c.get("dangerous")
        for c in children
    )
    report["nested_archive"] = any(c.get("family") in NESTED_ARCHIVE_FAMILIES
                                   and c.get("depth", 1) >= 1 for c in children) \
        and report["max_child_depth"] >= 2

    # JAR-specific static analysis: manifest, class names, IOCs from class bytes.
    if family == "jar":
        report["jar"] = _analyze_jar_metadata(path)

    return report


def _analyze_jar_metadata(path: str) -> dict:
    """Extract Java-specific metadata from a JAR without needing a JVM.

    What we look for:
      - MANIFEST.MF: Main-Class (makes it directly executable), Permissions, Application-Name
      - Class file names: attack-themed names like Exploit.class are a strong signal
      - Signing: the absence of META-INF/*.SF means the JAR is unsigned
      - IOCs extracted from the combined class file bytes
    """
    info: dict = {
        "manifest": {},
        "main_class": None,
        "class_files": [],
        "class_count": 0,
        "suspicious_class_names": [],
        "signed": False,
        "iocs": {},
    }

    SUSPICIOUS_KEYWORDS = {
        "exploit", "payload", "dropper", "shellcode", "loader", "injector",
        "backdoor", "trojan", "reverse", "meterpreter", "cobalt", "beacon",
        "keylog", "stealer", "dumper", "bypass", "obfusc", "crypter", "binder",
        "rat", "c2", "command", "invoke", "exec", "download", "upload",
    }

    try:
        with zipfile.ZipFile(path) as zf:
            names = zf.namelist()

            # Parse MANIFEST.MF
            manifest_paths = [n for n in names if n.upper() == "META-INF/MANIFEST.MF"]
            if manifest_paths:
                try:
                    raw = zf.read(manifest_paths[0]).decode("utf-8", "replace")
                    for line in raw.splitlines():
                        if ":" in line:
                            key, _, value = line.partition(":")
                            info["manifest"][key.strip()] = value.strip()
                    info["main_class"] = info["manifest"].get("Main-Class")
                except Exception:
                    pass

            # Enumerate class files
            class_files = [n for n in names if n.lower().endswith(".class")]
            info["class_count"] = len(class_files)
            info["class_files"] = class_files[:60]

            # Flag suspicious class names
            for cf in class_files:
                basename = os.path.splitext(os.path.basename(cf))[0].lower()
                hits = [kw for kw in SUSPICIOUS_KEYWORDS if kw in basename]
                if hits:
                    info["suspicious_class_names"].append({
                        "class": cf, "matched_keywords": hits
                    })

            # Check for signing (presence of META-INF/*.SF files)
            info["signed"] = any(
                n.upper().startswith("META-INF/") and n.upper().endswith(".SF")
                for n in names
            )

            # Extract IOCs from combined class bytes (cap at 8 MiB)
            class_bytes = b""
            total = 0
            for cf in class_files[:200]:
                try:
                    chunk = zf.read(cf)
                    class_bytes += chunk
                    total += len(chunk)
                    if total > 8 * 1024 * 1024:
                        break
                except Exception:
                    continue
            if class_bytes:
                info["iocs"] = common.extract_iocs(class_bytes)

    except Exception as exc:
        info["error"] = f"{type(exc).__name__}: {exc}"

    return info


def _collect_children(directory: str, workdir: str, out: list[dict],
                      depth: int, prefix: str) -> None:
    """Triage every extracted file; recurse into nested archives up to MAX_DEPTH."""
    for root, _dirs, files in os.walk(directory):
        for name in sorted(files):
            if len(out) >= MAX_CHILDREN * MAX_DEPTH:
                return
            child_path = os.path.join(root, name)
            rel = os.path.join(prefix, os.path.relpath(child_path, directory))
            try:
                tri = triage_mod.triage(child_path, os.path.basename(name))
            except Exception as exc:
                out.append({"name": rel, "error": str(exc), "depth": depth})
                continue
            dangerous = (tri["extension"] in triage_mod.DANGEROUS_EXTS
                         or tri["family"] in ("pe", "elf"))
            out.append({
                "name": rel, "path": child_path, "depth": depth,
                "family": tri["family"], "label": tri["label"], "size": tri["size"],
                "sha256": tri["sha256"], "entropy": tri["entropy"],
                "extension_mismatch": tri["extension_mismatch"],
                "filename_flags": tri["filename_flags"], "dangerous": dangerous,
            })
            # Recurse into a nested archive.
            if tri["family"] in NESTED_ARCHIVE_FAMILIES and depth < MAX_DEPTH:
                sub = os.path.join(workdir, f"nested_{depth}_{len(out)}")
                res = _extract(child_path, tri["family"], sub)
                if res.get("ok"):
                    _collect_children(sub, workdir, out, depth + 1, rel)
