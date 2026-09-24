"""Signature engine: the only place that turns observations into a judgement.

It lives on the API side on purpose. The worker image is large and slow to rebuild; this
file is small and changes often. Keeping the two apart means detection rules can be tuned
and redeployed in seconds, and an archived observation set can be re-scored later against
improved rules without re-detonating the sample.

Each rule is a pure function of the observation dict. `severity` is the contribution to a
0-100 score; scoring is saturating rather than additive (see `score`), so five weak hints
never add up to a false "malicious".
"""
from __future__ import annotations

from typing import Any, Callable

Rule = Callable[[dict], "list[dict] | dict | None"]
_RULES: list[tuple[str, str, int, str, Rule]] = []


def rule(sig_id: str, name: str, severity: int, description: str):
    def register(fn: Rule):
        _RULES.append((sig_id, name, severity, description, fn))
        return fn
    return register


def _get(obs: dict, *path: str, default=None) -> Any:
    node: Any = obs
    for key in path:
        if not isinstance(node, dict):
            return default
        node = node.get(key)
        if node is None:
            return default
    return node


# --------------------------------------------------------------- identity / packaging

@rule("FILE_EXT_MISMATCH", "File type does not match its extension", 45,
      "The file's real content type disagrees with the extension shown to the user. "
      "This is how a recipient is convinced to open an executable.")
def _ext_mismatch(obs):
    mismatch = _get(obs, "file", "extension_mismatch")
    return {"evidence": [mismatch]} if mismatch else None


@rule("FILE_NAME_DECEPTION", "Filename is built to deceive", 55,
      "The filename uses a technique whose only purpose is to misrepresent the file type "
      "to the person opening it.")
def _name_flags(obs):
    flags = _get(obs, "file", "filename_flags", default=[]) or []
    return {"evidence": flags} if flags else None


@rule("DANGEROUS_EXTENSION", "Directly executable attachment", 35,
      "The attachment is a file type that executes code when opened. Legitimate business "
      "mail almost never carries one.")
def _dangerous_ext(obs):
    if _get(obs, "file", "extension_is_dangerous"):
        return {"evidence": [f"extension {_get(obs, 'file', 'extension')}"]}
    return None


# ------------------------------------------------------------------------- Office

@rule("OFFICE_MACRO_PRESENT", "Document contains VBA macros", 30,
      "The document carries a VBA project. Macros are the classic Office delivery vector.")
def _macro_present(obs):
    macros = _get(obs, "static", "vba", "macros", default=[]) or []
    lines = _get(obs, "static", "vba", "total_macro_lines", default=0)
    if macros and lines:
        return {"evidence": [f"{len(macros)} macro stream(s), {lines} lines of VBA"]}
    return None


@rule("OFFICE_MACRO_AUTOEXEC", "Macro runs automatically on open", 55,
      "The macro is wired to an auto-execution trigger, so merely opening the document "
      "runs code -- no further user action is needed.")
def _autoexec(obs):
    triggers = _get(obs, "static", "vba", "auto_exec", default=[]) or []
    return {"evidence": [f"trigger: {t}" for t in triggers]} if triggers else None


@rule("OFFICE_MACRO_SHELL", "Macro spawns processes or downloads", 70,
      "The macro contains calls that start programs or fetch remote content. Combined with "
      "an auto-execution trigger this is a working dropper.")
def _macro_shell(obs):
    calls = _get(obs, "static", "vba", "suspicious_calls", default=[]) or []
    hot = [c for c in calls if c["keyword"] in {
        "shell", "wscript.shell", "powershell", "cmd.exe", "urldownloadtofile",
        "xmlhttp", "winhttprequest", "adodb.stream", "winmgmts", "mshta",
        "regsvr32", "rundll32", "certutil", "bitsadmin", "virtualalloc"}]
    if hot:
        return {"evidence": [f"{c['keyword']} -- {c['meaning']}" for c in hot]}
    return None


@rule("OFFICE_MACRO_OBFUSCATED", "Macro hides its own strings", 40,
      "The macro assembles strings at runtime to defeat static scanning. Benign macros "
      "have no reason to do this.")
def _macro_obf(obs):
    calls = _get(obs, "static", "vba", "suspicious_calls", default=[]) or []
    hiding = [c["keyword"] for c in calls
              if c["keyword"] in {"chr(", "chrw(", "strreverse", "base64", "frombase64string"}]
    rebuilt = _get(obs, "static", "vba", "deobfuscated", default=[]) or []
    if hiding or len(rebuilt) > 2:
        evidence = [f"obfuscation via {k}" for k in hiding]
        evidence += [f"reconstructed string: {s[:160]}" for s in rebuilt[:5]]
        return {"evidence": evidence}
    return None


@rule("OFFICE_REMOTE_TEMPLATE", "Remote template injection", 80,
      "The document pulls a template from a remote server on open. The delivered file is "
      "clean, so gateways pass it; the payload arrives afterwards from the attacker's host.")
def _remote_template(obs):
    target = _get(obs, "static", "package", "remote_template")
    return {"evidence": [f"attachedTemplate -> {target}"]} if target else None


@rule("OFFICE_EXTERNAL_REL", "Document references external resources", 35,
      "The OOXML package contains external relationship targets, which cause the document "
      "to reach out to a remote host when opened.")
def _external_rel(obs):
    targets = _get(obs, "static", "package", "external_targets", default=[]) or []
    if targets:
        return {"evidence": [f"{t['type']} -> {t['target']}" for t in targets[:8]]}
    return None


@rule("OFFICE_DDE", "DDE command execution", 75,
      "The document uses DDE/DDEAUTO field codes, which run a command without any macro "
      "being present -- so 'macros are disabled' does not protect the recipient.")
def _dde(obs):
    if _get(obs, "static", "dde", "found"):
        return {"evidence": [_get(obs, "static", "dde", "output", default="")[:400]]}
    return None


@rule("OFFICE_XLM_MACRO", "Excel 4.0 (XLM) macro indicators", 50,
      "Indicators of Excel 4.0 macros, which live in sheets rather than a VBA project and "
      "are missed by tooling that only looks for VBA.")
def _xlm(obs):
    if _get(obs, "static", "xlm_macros_indicated"):
        return {"evidence": ["Excel 4.0 macro markers found in the raw document"]}
    return None


@rule("OFFICE_EMBEDDED_OBJECT", "Embedded OLE object", 45,
      "An object is embedded in the document. This is how an executable is smuggled inside "
      "an otherwise ordinary-looking file for the user to double-click.")
def _embedded(obs):
    objects = _get(obs, "static", "package", "embedded_objects", default=[]) or []
    return {"evidence": objects[:10]} if objects else None


@rule("OFFICE_EMBEDDED_EXECUTABLE", "Document has an executable embedded in it", 75,
      "A complete Windows executable is embedded inside the document's bytes. A legitimate "
      "document has no reason to carry a PE file -- this is OLE-package payload smuggling.")
def _embedded_pe(obs):
    pes = _get(obs, "static", "embedded_executables", default=[]) or []
    if pes:
        return {"evidence": [f"PE header at byte offset {p.get('offset')}" for p in pes[:8]]}
    return None


# --------------------------------------------------------------------------- PDF

@rule("PDF_JAVASCRIPT", "PDF contains JavaScript", 45,
      "The PDF carries JavaScript. Legitimate business documents very rarely do.")
def _pdf_js(obs):
    if _get(obs, "static", "javascript_present"):
        blobs = _get(obs, "static", "javascript", default=[]) or []
        return {"evidence": [f"{len(blobs)} JavaScript block(s)"] +
                            [b[:200] for b in blobs[:2]]}
    return None


@rule("PDF_AUTO_ACTION", "PDF runs an action on open", 55,
      "An /OpenAction or additional-action trigger fires as soon as the document is opened.")
def _pdf_open(obs):
    action = _get(obs, "static", "structure", "open_action")
    pages = _get(obs, "static", "structure", "page_actions", default=[]) or []
    if action or pages:
        evidence = ([f"/OpenAction: {action[:250]}"] if action else []) + \
                   [f"page {p['page']} {p['key']}" for p in pages[:5]]
        return {"evidence": evidence}
    return None


@rule("PDF_LAUNCH_ACTION", "PDF can launch an external program", 80,
      "A /Launch action is present, which asks the reader to start a local executable.")
def _pdf_launch(obs):
    launches = _get(obs, "static", "structure", "launch_actions", default=[]) or []
    if launches or "/Launch" in (_get(obs, "static", "keywords", default={}) or {}):
        return {"evidence": launches[:5] or ["/Launch keyword present in the document"]}
    return None


@rule("PDF_EMBEDDED_FILE", "PDF has an embedded file", 55,
      "A file is embedded inside the PDF for the recipient to extract and open.")
def _pdf_embedded(obs):
    files = _get(obs, "static", "structure", "embedded_files", default=[]) or []
    if files:
        return {"evidence": [f"{f['name']} ({f.get('size')} bytes, "
                             f"entropy {f.get('entropy')})" for f in files[:8]]}
    return None


# ------------------------------------------------------------------------ archive

@rule("ARCHIVE_PASSWORD_PROTECTED", "Password-protected archive", 60,
      "The archive is encrypted, so no mail gateway or scanner can inspect it. In phishing "
      "the password is supplied in the email body precisely to defeat that scanning.")
def _archive_password(obs):
    if _get(obs, "static", "password_protected"):
        return {"evidence": ["archive contents are encrypted and could not be inspected"]}
    return None


@rule("ARCHIVE_DANGEROUS_CONTENT", "Archive contains executable content", 60,
      "The archive holds files that execute code when opened -- at any nesting depth.")
def _archive_dangerous(obs):
    entries = _get(obs, "static", "dangerous_entries", default=[]) or []
    evidence = [f"{e['name']} ({e.get('extension')})" for e in entries[:10]]
    # Executable content found by recursing into the archive (and nested archives).
    exec_children = [c for c in (_get(obs, "static", "children", default=[]) or [])
                     if c.get("family") in ("pe", "elf") or c.get("dangerous")]
    for c in exec_children[:10]:
        tag = f"depth {c.get('depth', 1)}" if c.get("depth", 1) > 1 else "top level"
        evidence.append(f"{c.get('name')} -> {c.get('label', c.get('family'))} ({tag})")
    return {"evidence": evidence} if evidence else None


@rule("ARCHIVE_NESTED_EXECUTABLE", "Executable hidden inside a nested archive", 65,
      "An executable is buried inside an archive-within-an-archive. Nesting archives is a "
      "common way to slip a payload past gateways that only scan the outer layer.")
def _archive_nested(obs):
    children = _get(obs, "static", "children", default=[]) or []
    deep = [c for c in children
            if c.get("depth", 1) >= 2 and (c.get("family") in ("pe", "elf") or c.get("dangerous"))]
    if deep:
        return {"evidence": [f"{c.get('name')} at depth {c.get('depth')} "
                             f"({c.get('label', c.get('family'))})" for c in deep[:10]]}
    return None


@rule("ARCHIVE_DECOY_NAME", "Archive hides a file's real type", 70,
      "A file inside the archive is named to look like a document or image while actually "
      "being executable.")
def _archive_decoy(obs):
    decoys = _get(obs, "static", "decoy_names", default=[]) or []
    if decoys:
        return {"evidence": [f"{d['name']} -- {d['reason']}" for d in decoys[:10]]}
    return None


@rule("ARCHIVE_TRAVERSAL", "Archive contains path traversal", 65,
      "An entry escapes the extraction directory, letting extraction overwrite files "
      "elsewhere on the system.")
def _archive_traversal(obs):
    paths = _get(obs, "static", "path_traversal", default=[]) or []
    return {"evidence": paths[:10]} if paths else None


@rule("ARCHIVE_BOMB", "Possible decompression bomb", 40,
      "The compression ratio is high enough to exhaust storage or memory on extraction.")
def _archive_bomb(obs):
    if _get(obs, "static", "zip_bomb_suspected"):
        ratio = _get(obs, "static", "listing", "compression_ratio")
        return {"evidence": [f"compression ratio {ratio}:1"]}
    return None


@rule("ARCHIVE_CHILD_MISMATCH", "Archived file misrepresents its type", 55,
      "A file inside the archive has content that disagrees with its extension.")
def _archive_child(obs):
    children = _get(obs, "static", "children", default=[]) or []
    bad = [c for c in children if c.get("extension_mismatch") or c.get("filename_flags")]
    if bad:
        return {"evidence": [f"{c['name']}: {c.get('extension_mismatch') or c['filename_flags']}"
                             for c in bad[:8]]}
    return None


# --------------------------------------------------------------------------- PE

@rule("PE_PACKED", "Executable is packed or obfuscated", 45,
      "The binary is compressed or protected, hiding its real code from static inspection. "
      "Commercial software is sometimes packed; phishing payloads nearly always are.")
def _pe_packed(obs):
    packers = _get(obs, "static", "pe", "packer_sections", default=[]) or []
    sections = _get(obs, "static", "pe", "sections", default=[]) or []
    high = [s for s in sections if s.get("entropy", 0) > 7.2 and s.get("raw_size", 0) > 4096]
    stripped = _get(obs, "static", "pe", "import_table_stripped")
    evidence = []
    if packers:
        evidence.append(f"known packer sections: {', '.join(packers)}")
    if high:
        evidence += [f"section {s['name']} entropy {s['entropy']}" for s in high[:5]]
    if stripped:
        evidence.append("import table has almost no entries; APIs are resolved at runtime")
    return {"evidence": evidence} if evidence else None


@rule("PE_SELF_MODIFYING", "Executable has writable+executable sections", 50,
      "A section is both writable and executable, which is how an unpacking stub or "
      "injected shellcode runs. Compilers do not normally produce this.")
def _pe_wx(obs):
    sections = _get(obs, "static", "pe", "sections", default=[]) or []
    wx = [s for s in sections if s.get("write_and_execute")]
    if wx:
        return {"evidence": [f"section {s['name']} is W+X" for s in wx[:5]]}
    return None


@rule("PE_INJECTION_CAPABLE", "Binary can inject code into other processes", 65,
      "The import table contains the standard process-injection API set.")
def _pe_inject(obs):
    caps = _get(obs, "static", "pe", "capabilities", default={}) or {}
    if "process_injection" in caps:
        return {"evidence": caps["process_injection"][:10]}
    return None


@rule("PE_ANTI_ANALYSIS", "Binary checks whether it is being analysed", 50,
      "The binary imports debugger-detection and timing APIs, so it can behave differently "
      "inside a sandbox than on a victim machine.")
def _pe_anti(obs):
    caps = _get(obs, "static", "pe", "capabilities", default={}) or {}
    if "anti_analysis" in caps:
        return {"evidence": caps["anti_analysis"][:10]}
    return None


@rule("PE_CAPABILITY_MIX", "Binary combines download, persistence and execution", 60,
      "The import table shows the full dropper pattern: fetch remote content, write it, "
      "make it run, and survive a reboot.")
def _pe_mix(obs):
    caps = _get(obs, "static", "pe", "capabilities", default={}) or {}
    present = {k for k in ("network", "persistence", "process_control",
                           "credential_access", "keylogging") if k in caps}
    if len(present) >= 3:
        return {"evidence": [f"capability groups present: {', '.join(sorted(present))}"]}
    return None


@rule("PE_EMBEDDED_EXECUTABLE", "Executable carries another executable inside it", 65,
      "A second PE file is hidden in a resource or in the overlay -- the stage 2 payload.")
def _pe_embedded(obs):
    evidence = []
    for res in _get(obs, "static", "pe", "resources", default=[]) or []:
        if res.get("looks_executable"):
            evidence.append(f"resource {res['type']} contains a PE ({res['size']} bytes)")
    overlay = _get(obs, "static", "pe", "overlay", default={}) or {}
    if overlay.get("looks_executable"):
        evidence.append(f"overlay contains a PE ({overlay.get('size')} bytes)")
    elif overlay.get("size", 0) > 65536 and overlay.get("entropy", 0) > 7.0:
        evidence.append(f"high-entropy overlay of {overlay['size']} bytes "
                        f"(entropy {overlay['entropy']})")
    return {"evidence": evidence} if evidence else None


@rule("PE_UNSIGNED", "Executable is not digitally signed", 20,
      "No Authenticode signature. On its own this is weak -- most small tools are unsigned "
      "-- but it removes the main reason to trust an executable arriving by email.")
def _pe_unsigned(obs):
    if _get(obs, "static", "pe", "parsed") and not _get(obs, "static", "pe", "digitally_signed"):
        return {"evidence": ["no Authenticode signature present"]}
    return None


@rule("PE_FAKE_TIMESTAMP", "Compile timestamp is implausible", 30,
      "The PE header's compile time is in the future or impossibly old, meaning it was "
      "deliberately altered.")
def _pe_timestamp(obs):
    if _get(obs, "static", "pe", "timestamp_implausible"):
        return {"evidence": [f"compile time reported as "
                             f"{_get(obs, 'static', 'pe', 'compile_time')}"]}
    return None


# ------------------------------------------------------------------------ script

@rule("SCRIPT_OBFUSCATED", "Script is obfuscated", 50,
      "The script hides its logic behind encoding or string reconstruction. There is no "
      "benign reason for an emailed script to do this.")
def _script_obf(obs):
    deob = _get(obs, "static", "deobfuscated", default={}) or {}
    rebuilt = sum(len(v) for v in deob.values() if isinstance(v, list))
    single_line = _get(obs, "static", "single_line_obfuscation")
    entropy = _get(obs, "static", "entropy", default=0)
    evidence = []
    if rebuilt:
        evidence.append(f"{rebuilt} string(s) reconstructed from runtime obfuscation")
        for values in deob.values():
            for value in (values or [])[:2]:
                evidence.append(f"reconstructed: {value[:160]}")
    if single_line:
        evidence.append(f"one line of {_get(obs, 'static', 'longest_line')} characters")
    if entropy and entropy > 5.6:
        evidence.append(f"source entropy {entropy}")
    return {"evidence": evidence[:8]} if evidence else None


@rule("SCRIPT_ENCODED_PAYLOAD", "Script carries an encoded payload", 55,
      "A long base64 blob is embedded in the script. This is how a second stage is shipped "
      "inside a text file.")
def _script_b64(obs):
    blobs = _get(obs, "static", "base64_blobs", default=[]) or []
    big = [b for b in blobs if b.get("encoded_length", 0) > 200]
    if big:
        evidence = [f"{b['encoded_length']} chars, {b['encoding']}, entropy {b['entropy']}"
                    + (", decodes to a PE file" if b.get("looks_like_pe") else "")
                    for b in big[:5]]
        return {"evidence": evidence}
    return None


@rule("SCRIPT_POWERSHELL_ABUSE", "PowerShell invoked with evasive flags", 70,
      "PowerShell is used with the flag combination that hides the window, skips profile "
      "logging and bypasses execution policy -- the standard malicious invocation.")
def _ps_abuse(obs):
    indicators = _get(obs, "static", "powershell_indicators", default=[]) or []
    if len(indicators) >= 2:
        return {"evidence": [f"{i['flag']} -- {i['meaning']}" for i in indicators[:10]]}
    return None


@rule("SCRIPT_DROPPER_BEHAVIOUR", "Script emulation resolved a download URL", 85,
      "Emulating the script made it reveal the address it fetches its payload from. This is "
      "observed behaviour, not a guess from the source text.")
def _dropper(obs):
    urls = _get(obs, "dynamic", "extracted_urls", default=[]) or []
    resources = _get(obs, "dynamic", "resources", default=[]) or []
    evidence = [f"resolved URL: {u}" for u in urls[:8]]
    evidence += [f"dropped {r['name']} ({r['size']} bytes)"
                 + (", a PE file" if r.get("looks_like_pe") else "") for r in resources[:5]]
    return {"evidence": evidence} if evidence else None


# ---------------------------------------------------------------------- dynamic

@rule("DYN_PROCESS_SPAWN", "Sample spawned processes when run", 60,
      "Executing the sample started other programs. The command lines are recorded below.")
def _dyn_proc(obs):
    procs = _get(obs, "dynamic", "processes", default=[]) or []
    if procs:
        return {"evidence": [p["command"][:300] for p in procs[:10]]}
    return None


@rule("DYN_LOLBIN", "Sample invoked a living-off-the-land binary", 70,
      "The sample called a trusted system utility to do its work, which is how malicious "
      "activity is made to look like normal administration.")
def _dyn_lolbin(obs):
    bins = _get(obs, "dynamic", "lolbins_invoked", default=[]) or []
    return {"evidence": bins[:10]} if bins else None


@rule("DYN_NETWORK", "Sample attempted network communication", 70,
      "The sample tried to reach a remote host. It could not -- the detonation network has "
      "no route off this machine -- but the attempt and its destination were recorded.")
def _dyn_net(obs):
    dns = _get(obs, "network", "dns_queries", default=[]) or []
    http = _get(obs, "network", "http_requests", default=[]) or []
    connects = _get(obs, "network", "connect_attempts", default=[]) or []
    evidence = [f"DNS lookup for {q.get('qname')}" for q in dns[:8]]
    evidence += [f"{r.get('method')} {r.get('scheme')}://{r.get('host')}{r.get('path')}"
                 for r in http[:8]]
    evidence += [f"TCP connect to {c.get('ip')}:{c.get('port')}" for c in connects[:8]]
    return {"evidence": evidence} if evidence else None


@rule("DYN_EXFIL_ATTEMPT", "Sample tried to send data out", 75,
      "An outbound request carried a body, meaning the sample was uploading something.")
def _dyn_exfil(obs):
    http = _get(obs, "network", "http_requests", default=[]) or []
    posts = [r for r in http if r.get("method") in ("POST", "PUT") and r.get("body_len", 0) > 0]
    if posts:
        return {"evidence": [f"{r['method']} to {r.get('host')}{r.get('path')} "
                             f"with {r['body_len']} bytes of body" for r in posts[:6]]}
    return None


@rule("DYN_PERSISTENCE", "Sample established persistence", 80,
      "The sample wrote to a location that causes it to run again after a reboot or login.")
def _dyn_persist(obs):
    paths = _get(obs, "dynamic", "persistence_paths", default=[]) or []
    if paths:
        return {"evidence": [f"{p['path']} -- {p['meaning']}" for p in paths[:10]]}
    return None


@rule("DYN_DROPPED_EXECUTABLE", "Sample wrote a file and made it executable", 75,
      "The sample created a file on disk and then set the execute bit on it -- the drop "
      "half of a dropper.")
def _dyn_drop(obs):
    execs = _get(obs, "dynamic", "made_executable", default=[]) or []
    if execs:
        return {"evidence": [f"chmod {e['mode']} {e['path']}" for e in execs[:10]]}
    return None


@rule("DYN_ANON_EXEC", "Sample executed code from memory", 70,
      "The sample created an anonymous in-memory file and ran from it, leaving nothing on "
      "disk for a file scanner to find.")
def _dyn_memfd(obs):
    memfds = _get(obs, "dynamic", "anonymous_executables", default=[]) or []
    return {"evidence": memfds[:10]} if memfds else None


@rule("DYN_FILE_DESTRUCTION", "Sample deleted files", 45,
      "The sample removed files during execution, which is either self-cleanup to hide "
      "traces or destructive behaviour.")
def _dyn_delete(obs):
    deleted = _get(obs, "dynamic", "files_deleted", default=[]) or []
    if len(deleted) >= 2:
        return {"evidence": deleted[:10]}
    return None


# --------------------------------------------------------------------- indicators

@rule("IOC_SUSPICIOUS_TLD", "Reference to a high-abuse top-level domain", 30,
      "The sample references a domain on a TLD that is disproportionately used for abuse "
      "because registrations there are free or unverified.")
def _bad_tld(obs):
    bad = (".tk", ".ml", ".ga", ".cf", ".gq", ".top", ".xyz", ".icu", ".click",
           ".zip", ".mov", ".su", ".pw", ".cc", ".live", ".shop")
    domains = _get(obs, "iocs", "domains", default=[]) or []
    hits = [d for d in domains if d.endswith(bad)]
    return {"evidence": hits[:10]} if hits else None


@rule("IOC_RAW_IP_URL", "URL points directly at an IP address", 40,
      "A URL uses a bare IP instead of a hostname. Legitimate services use names; this "
      "avoids domain reputation and DNS logging.")
def _ip_url(obs):
    import re as _re
    urls = _get(obs, "iocs", "urls", default=[]) or []
    hits = [u for u in urls if _re.match(r"https?://\d{1,3}(\.\d{1,3}){3}", u)]
    return {"evidence": hits[:10]} if hits else None


@rule("IOC_EXECUTABLE_URL", "URL fetches an executable", 55,
      "A referenced URL ends in an executable or script extension, so following it "
      "downloads code.")
def _exe_url(obs):
    bad_ext = (".exe", ".dll", ".scr", ".ps1", ".vbs", ".js", ".hta", ".bat", ".cmd",
               ".msi", ".jar", ".zip", ".7z", ".iso")
    urls = _get(obs, "iocs", "urls", default=[]) or []
    hits = [u for u in urls if u.split("?")[0].lower().endswith(bad_ext)]
    return {"evidence": hits[:10]} if hits else None


# ----------------------------------------------------------------------- JAR

@rule("JAR_SUSPICIOUS_MANIFEST", "Java archive has executable or suspicious traits", 50,
      "The JAR has traits seen in weaponised Java attachments: a Main-Class entry that "
      "makes it directly executable, class names containing attack-related keywords, or "
      "no digital signature.")
def _jar_manifest(obs):
    jar = _get(obs, "static", "jar", default={}) or {}
    if not jar:
        return None
    evidence = []
    main_class = jar.get("main_class")
    if main_class:
        evidence.append(f"Main-Class: {main_class} (directly executable)")
    suspicious = jar.get("suspicious_class_names", []) or []
    for s in suspicious[:5]:
        evidence.append(f"suspicious class: {s['class']} (keywords: {', '.join(s['matched_keywords'])})")
    if not jar.get("signed"):
        evidence.append("JAR is not digitally signed")
    class_count = jar.get("class_count", 0)
    if class_count:
        evidence.append(f"{class_count} class file(s)")
    # Only fire if there's something genuinely suspicious beyond just being unsigned
    if main_class or suspicious:
        return {"evidence": evidence}
    # If unsigned with many classes, still note it but at reduced confidence
    if not jar.get("signed") and class_count > 0:
        return {"evidence": evidence}
    return None


# ----------------------------------------------------------------- XLM hidden sheets

@rule("OFFICE_XLM_HIDDEN_SHEET", "Hidden Excel 4.0 macro sheet detected", 65,
      "A BIFF8 Boundsheet record marks a macro sheet as hidden or very-hidden. Hiding "
      "the macro sheet has no legitimate purpose -- it is done specifically to evade "
      "inspection and keep the sheet out of the tab bar.")
def _xlm_hidden(obs):
    sheets = _get(obs, "static", "xlm_biff8_sheets", default=[]) or []
    hidden = [s for s in sheets if s.get("hidden")]
    if hidden:
        return {"evidence": [f"sheet '{s['name']}' is {s['visibility']} ({s['type']})"
                             for s in hidden[:10]]}
    # Even a visible XLM macro sheet is worth noting if BIFF8 parsing found it
    if sheets:
        return {"evidence": [f"sheet '{s['name']}' is a {s['type']} sheet"
                             for s in sheets[:10]]}
    return None


# --------------------------------------------------------- binary string IOCs

@rule("IOC_SUSPICIOUS_DOMAIN_IN_BINARY", "Binary contains abuse-related domain names", 45,
      "The string table contains domain names associated with DDoS services, botnets, "
      "C2 infrastructure, or other attack tools.")
def _binary_abuse_domains(obs):
    # Only applies to PE/ELF families
    family = _get(obs, "file", "family")
    if family not in ("pe", "elf"):
        return None
    domains = _get(obs, "iocs", "domains", default=[]) or []
    static_domains = (_get(obs, "static", "file_iocs", "domains", default=[]) or [])
    all_domains = list(set(domains + static_domains))

    ABUSE_KEYWORDS = (
        "ddos", "botnet", "c2", "cnc", "rat", "exploit", "malware", "trojan",
        "stealer", "loader", "dropper", "phish", "keylog", "ransom", "miner",
        "flood", "attack", "shell", "hack", "brute",
    )
    hits = []
    for d in all_domains:
        lowered = d.lower()
        for kw in ABUSE_KEYWORDS:
            if kw in lowered:
                hits.append(f"{d} (matches '{kw}')")
                break
    return {"evidence": hits[:10]} if hits else None


@rule("IOC_HARDCODED_IP_IN_BINARY", "Binary has hardcoded remote IP addresses", 40,
      "Non-private, non-loopback IP addresses are embedded in the binary. Legitimate "
      "software uses hostnames; hardcoded IPs avoid DNS logging and domain reputation.")
def _binary_hardcoded_ips(obs):
    import re as _re
    family = _get(obs, "file", "family")
    if family not in ("pe", "elf"):
        return None
    ips = _get(obs, "iocs", "ips", default=[]) or []
    static_ips = (_get(obs, "static", "file_iocs", "ips", default=[]) or [])
    all_ips = list(set(ips + static_ips))

    # Filter out private, loopback, link-local, documentation, and multicast ranges
    def _is_suspicious(ip: str) -> bool:
        parts = ip.split(".")
        if len(parts) != 4:
            return False
        try:
            octets = [int(p) for p in parts]
        except ValueError:
            return False
        # Skip private / special ranges
        if octets[0] == 10:
            return False
        if octets[0] == 172 and 16 <= octets[1] <= 31:
            return False
        if octets[0] == 192 and octets[1] == 168:
            return False
        if octets[0] == 127:
            return False
        if octets[0] == 169 and octets[1] == 254:
            return False
        if octets[0] in (224, 239, 240, 255):
            return False
        if octets[0] == 192 and octets[1] == 0 and octets[2] == 2:
            return False  # TEST-NET-1 (RFC 5737)
        if octets[0] == 198 and octets[1] == 51 and octets[2] == 100:
            return False  # TEST-NET-2
        if octets[0] == 203 and octets[1] == 0 and octets[2] == 113:
            return False  # TEST-NET-3
        # Skip version-like patterns (e.g. 1.9.1.1)
        if all(o < 10 for o in octets):
            return False
        return True

    suspicious = [ip for ip in all_ips if _is_suspicious(ip)]
    return {"evidence": suspicious[:10]} if suspicious else None


# ----------------------------------------------------------------------- scoring

def evaluate(observations: dict) -> list[dict]:
    """Run every rule. A rule that raises is a bug in the rule, not a reason to lose the job."""
    fired: list[dict] = []
    for sig_id, name, severity, description, fn in _RULES:
        try:
            result = fn(observations)
        except Exception as exc:  # pragma: no cover - defensive
            fired.append({
                "id": "RULE_ERROR", "name": f"rule {sig_id} failed", "severity": 0,
                "description": "This detection rule raised an exception and was skipped.",
                "evidence": [f"{type(exc).__name__}: {exc}"],
            })
            continue
        if not result:
            continue
        evidence = [str(e) for e in (result.get("evidence") or []) if e]
        fired.append({"id": sig_id, "name": name, "severity": severity,
                      "description": description, "evidence": evidence[:12]})
    return sorted(fired, key=lambda s: -s["severity"])


def score(signatures: list[dict]) -> tuple[int, str, float]:
    """Rank-decayed saturating combination, not a sum.

    Two properties matter for a phishing verdict:
      - One strong finding (a remote-template injection, a resolved dropper URL) should be
        enough on its own -- it must not need corroboration to reach 'malicious'.
      - A pile of individually weak findings must NOT add up to 'malicious'. A dozen
        20-point hints is a document worth a look, not a confirmed threat.

    A plain saturating product gives the first property but fails the second (ten 20s reach
    ~89). So each signature's contribution is decayed by its severity rank before the
    saturating combine: the strongest finding counts in full, the next at 60%, then 36%,
    and so on. The dominant signal still dominates, but weak signals fade fast enough that
    they can only ever push a verdict up to 'suspicious'.
    """
    real = [s for s in signatures if s["id"] != "RULE_ERROR"]
    remaining = 100.0
    for rank, sig in enumerate(sorted(real, key=lambda s: -s["severity"])):
        weight = (sig["severity"] / 100.0) * (0.6 ** rank)
        remaining *= (1.0 - weight)
    value = int(round(100.0 - remaining))

    if value >= 70:
        level = "malicious"
    elif value >= 35:
        level = "suspicious"
    else:
        level = "benign"

    # Confidence tracks the strength of the best single finding and how much corroborates
    # it -- not the score, which can be high off many weak hints.
    top = max((s["severity"] for s in real), default=0)
    corroboration = min(len([s for s in real if s["severity"] >= 40]), 4) / 4.0
    confidence = round(min(0.95, 0.35 + 0.45 * (top / 100.0) + 0.20 * corroboration), 2)
    if not real:
        confidence = 0.5

    return value, level, confidence
