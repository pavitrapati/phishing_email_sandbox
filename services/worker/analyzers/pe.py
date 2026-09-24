"""Windows PE (exe/dll/scr/msi) and ELF static analysis.

Real PE detonation needs Windows semantics, so on Linux this is static plus an optional
Wine run (see behaviour.py). What static analysis gives us reliably: packing, import
capability, resource smuggling, overlay payloads, signing status, and compile timestamps.
That is usually enough to call a phishing attachment, and it never lies about what it saw.
"""
from __future__ import annotations

import struct
from datetime import datetime, timezone

from . import common

# Import name -> capability it implies. Grouped so the report can say *what the binary can do*
# rather than dumping 300 API names at the language model.
IMPORT_CAPABILITIES = {
    "network": ["internetopen", "internetconnect", "httpsendrequest", "httpopenrequest",
                "urldownloadtofile", "winhttpopen", "winhttpconnect", "wsastartup",
                "connect", "send", "recv", "gethostbyname", "getaddrinfo", "socket",
                "dnsquery", "internetreadfile", "ftpputfile"],
    "process_injection": ["virtualallocex", "writeprocessmemory", "createremotethread",
                          "ntunmapviewofsection", "setthreadcontext", "queueuserapc",
                          "ntwritevirtualmemory", "rtlcreateuserthread", "openprocess",
                          "zwunmapviewofsection", "mapviewofsection", "ntmapviewofsection"],
    "process_control": ["createprocess", "shellexecute", "winexec", "createthread",
                        "terminateprocess", "openprocesstoken", "createprocessinternal"],
    "persistence": ["regcreatekey", "regsetvalue", "regopenkey", "createservice",
                    "openscmanager", "startservice", "schtasks", "netscheduleadd"],
    "anti_analysis": ["isdebuggerpresent", "checkremotedebuggerpresent", "outputdebugstring",
                      "ntqueryinformationprocess", "getickcount", "gettickcount",
                      "queryperformancecounter", "sleep", "createtoolhelp32snapshot",
                      "process32first", "process32next", "findwindow", "blockinput"],
    "credential_access": ["cryptunprotectdata", "credenumerate", "lsaretrieveprivatedata",
                          "samconnect", "netuseradd", "wnetenumresource"],
    "keylogging": ["setwindowshookex", "getasynckeystate", "getkeystate", "getforegroundwindow",
                   "registerrawinputdevices", "getrawinputdata"],
    "crypto": ["cryptencrypt", "cryptdecrypt", "cryptgenkey", "cryptacquirecontext",
               "bcryptencrypt", "cryptcreatehash", "cryptderivekey"],
    "dynamic_resolution": ["loadlibrary", "getprocaddress", "ldrloaddll", "ldrgetprocedureaddress"],
    "screen_capture": ["bitblt", "getdc", "createcompatiblebitmap", "printwindow"],
    "file_destruction": ["deletefile", "movefileex", "setfileattributes", "findfirstfile"],
}

PACKER_SECTIONS = {
    ".aspack": "ASPack", ".adata": "ASPack", "upx0": "UPX", "upx1": "UPX", "upx2": "UPX",
    ".upx": "UPX", ".petite": "Petite", ".mpress1": "MPRESS", ".mpress2": "MPRESS",
    ".themida": "Themida", ".vmp0": "VMProtect", ".vmp1": "VMProtect", ".vmp2": "VMProtect",
    ".enigma1": "Enigma", ".enigma2": "Enigma", ".nsp0": "NsPack", ".packed": "generic packer",
    ".boom": "generic packer", ".ccg": "CCG", ".charmve": "PIN tool", ".taz": "PESpin",
    "pec1": "PECompact", "pec2": "PECompact", ".rlp": "RLPack", ".y0da": "yoda",
}


def _capabilities(imports: list[str]) -> dict[str, list[str]]:
    lowered = [i.lower() for i in imports]
    found: dict[str, list[str]] = {}
    for capability, needles in IMPORT_CAPABILITIES.items():
        hits = sorted({imp for imp in lowered if any(n in imp for n in needles)})
        if hits:
            found[capability] = hits[:25]
    return found


def _analyze_pe(path: str) -> dict:
    try:
        import pefile
    except ImportError:
        return {"parsed": False, "error": "pefile not installed"}

    try:
        pe = pefile.PE(path, fast_load=False)
    except Exception as exc:
        return {"parsed": False, "error": f"{type(exc).__name__}: {exc}"}

    info: dict = {"parsed": True}
    try:
        info["machine"] = pefile.MACHINE_TYPE.get(pe.FILE_HEADER.Machine, pe.FILE_HEADER.Machine)
        info["is_dll"] = bool(pe.is_dll())
        info["is_driver"] = bool(pe.is_driver())
        info["subsystem"] = pefile.SUBSYSTEM_TYPE.get(
            pe.OPTIONAL_HEADER.Subsystem, pe.OPTIONAL_HEADER.Subsystem)
        ts = pe.FILE_HEADER.TimeDateStamp
        info["compile_timestamp"] = ts
        try:
            compiled = datetime.fromtimestamp(ts, tz=timezone.utc)
            info["compile_time"] = compiled.isoformat()
            now = datetime.now(timezone.utc)
            # A timestamp in the future or before Win32 existed means it was tampered with.
            info["timestamp_implausible"] = compiled > now or compiled.year < 1995
        except (ValueError, OSError, OverflowError):
            info["compile_time"] = None
            info["timestamp_implausible"] = True
        info["entry_point"] = hex(pe.OPTIONAL_HEADER.AddressOfEntryPoint)
        info["image_base"] = hex(pe.OPTIONAL_HEADER.ImageBase)
    except Exception:
        pass

    sections = []
    packers = set()
    entry_rva = getattr(pe.OPTIONAL_HEADER, "AddressOfEntryPoint", 0)
    entry_section = None
    for section in pe.sections:
        name = section.Name.rstrip(b"\x00").decode("utf-8", "replace")
        data = section.get_data()
        characteristics = section.Characteristics
        record = {
            "name": name,
            "virtual_size": section.Misc_VirtualSize,
            "raw_size": section.SizeOfRawData,
            "entropy": common.entropy(data[:1024 * 1024]),
            "writable": bool(characteristics & 0x80000000),
            "executable": bool(characteristics & 0x20000000),
        }
        # W+X is legitimate almost nowhere; it is the classic unpacking stub giveaway.
        record["write_and_execute"] = record["writable"] and record["executable"]
        # Virtual size far exceeding raw size means the section is filled at runtime.
        record["virtual_oversize"] = (
            section.SizeOfRawData > 0
            and section.Misc_VirtualSize > section.SizeOfRawData * 4
        ) or (section.SizeOfRawData == 0 and section.Misc_VirtualSize > 0x1000)
        if section.contains_rva(entry_rva):
            entry_section = name
        if name.lower() in PACKER_SECTIONS:
            packers.add(PACKER_SECTIONS[name.lower()])
        sections.append(record)

    info["sections"] = sections
    info["packer_sections"] = sorted(packers)
    info["entry_point_section"] = entry_section
    # Entry point outside .text is normal for packers, rare for compilers.
    info["entry_outside_code"] = entry_section is not None and entry_section.lower() not in (
        ".text", "code", ".itext", ".textbss")

    imports: list[str] = []
    libraries: list[str] = []
    for entry in getattr(pe, "DIRECTORY_ENTRY_IMPORT", []) or []:
        lib = entry.dll.decode("utf-8", "replace") if entry.dll else "?"
        libraries.append(lib)
        for imp in entry.imports:
            if imp.name:
                imports.append(imp.name.decode("utf-8", "replace"))
    info["imported_libraries"] = sorted(set(libraries))
    info["import_count"] = len(imports)
    info["capabilities"] = _capabilities(imports)
    # A PE with almost no imports resolves them at runtime -- a packing indicator.
    info["import_table_stripped"] = len(imports) < 10

    exports = []
    for exp in getattr(getattr(pe, "DIRECTORY_ENTRY_EXPORT", None), "symbols", []) or []:
        if exp.name:
            exports.append(exp.name.decode("utf-8", "replace"))
    info["exports"] = exports[:60]

    resources = []
    for rtype in getattr(getattr(pe, "DIRECTORY_ENTRY_RESOURCE", None), "entries", []) or []:
        type_name = str(rtype.name) if rtype.name else pefile.RESOURCE_TYPE.get(
            rtype.struct.Id, f"id_{rtype.struct.Id}")
        for rid in getattr(rtype.directory, "entries", []) or []:
            for lang in getattr(rid.directory, "entries", []) or []:
                try:
                    data = pe.get_data(lang.data.struct.OffsetToData, lang.data.struct.Size)
                except Exception:
                    continue
                resources.append({
                    "type": type_name,
                    "size": lang.data.struct.Size,
                    "entropy": common.entropy(data[:262144]),
                    # A PE hidden in a resource is a dropper's stage 2.
                    "looks_executable": data[:2] == b"MZ",
                })
    info["resources"] = resources[:40]

    # Overlay: bytes appended past the last section. Used to smuggle configs and stage 2.
    try:
        overlay_offset = pe.get_overlay_data_start_offset()
        if overlay_offset is not None:
            overlay = pe.__data__[overlay_offset:]
            info["overlay"] = {
                "offset": overlay_offset,
                "size": len(overlay),
                "entropy": common.entropy(overlay[:1024 * 1024]),
                "looks_executable": overlay[:2] == b"MZ",
            }
    except Exception:
        pass

    info["digitally_signed"] = bool(
        getattr(pe, "OPTIONAL_HEADER", None)
        and len(pe.OPTIONAL_HEADER.DATA_DIRECTORY) > 4
        and pe.OPTIONAL_HEADER.DATA_DIRECTORY[4].VirtualAddress != 0
        and pe.OPTIONAL_HEADER.DATA_DIRECTORY[4].Size != 0
    )
    try:
        info["imphash"] = pe.get_imphash()
    except Exception:
        info["imphash"] = None

    pe.close()
    return info


def _analyze_elf(path: str) -> dict:
    with open(path, "rb") as fh:
        head = fh.read(64)
    if len(head) < 20:
        return {"parsed": False, "error": "truncated"}
    is_64 = head[4] == 2
    little = head[5] == 1
    endian = "<" if little else ">"
    etype, machine = struct.unpack(endian + "HH", head[16:20])
    readelf = common.run(["readelf", "-hdS", path], timeout=20)
    nm = common.run(["nm", "-D", "--defined-only", path], timeout=20)
    return {
        "parsed": True,
        "class": "ELF64" if is_64 else "ELF32",
        "endian": "little" if little else "big",
        "type": {1: "REL", 2: "EXEC", 3: "DYN/PIE", 4: "CORE"}.get(etype, str(etype)),
        "machine": machine,
        "readelf": common.truncate(readelf["stdout"], 4000),
        "dynamic_symbols": common.truncate(nm["stdout"], 2000),
    }


def analyze(path: str, tri: dict) -> dict:
    report: dict = {"engine": "pe"}
    if tri["family"] == "pe":
        report["pe"] = _analyze_pe(path)
    elif tri["family"] == "elf":
        report["elf"] = _analyze_elf(path)

    with open(path, "rb") as fh:
        raw = fh.read(16 * 1024 * 1024)
    report["strings_sample"] = common.strings(raw, min_len=8, limit=250)
    report["file_iocs"] = common.extract_iocs(raw)
    report["overall_entropy"] = common.entropy(raw[: 4 * 1024 * 1024])
    return report
