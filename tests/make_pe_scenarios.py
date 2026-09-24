#!/usr/bin/env python3
"""Extra scenarios: PE/DLL attachments and malware embedded inside other attachments.

Everything here is INERT. The PEs are either the cross-compiled inert dropper (which only
touches sinkholed/RFC-reserved destinations) or structurally-valid stubs. The point is to
prove the sandbox's routing and detection on the delivery tricks that actually carry
Windows malware into an inbox: raw .exe/.dll, decoy extensions, OLE-embedded objects,
password-protected and nested archives.
"""
from __future__ import annotations

import os
import struct
import zipfile

HERE = os.path.dirname(os.path.abspath(__file__))
OUT = os.path.join(HERE, "samples")
DROPPER = os.path.join(OUT, "dropper.exe")  # the real cross-compiled inert PE


def w(name: str, data: bytes) -> str:
    p = os.path.join(OUT, name)
    with open(p, "wb") as fh:
        fh.write(data)
    return p


def _valid_dll() -> bytes:
    """A structurally valid PE marked as a DLL, with an export directory and network-ish
    import names, so the PE analyzer reports is_dll + capabilities without needing to run."""
    dos = bytearray(0x80); dos[0:2] = b"MZ"; dos[0x3C:0x40] = struct.pack("<I", 0x80)
    # COFF: DLL characteristic (0x2000) + executable image
    coff = struct.pack("<HHIIIHH", 0x8664, 2, 0x5F000000, 0, 0, 0xF0, 0x2022)
    opt = bytearray(0xF0)
    struct.pack_into("<H", opt, 0, 0x20B)            # PE32+
    struct.pack_into("<I", opt, 16, 0x1000)          # entry
    struct.pack_into("<Q", opt, 24, 0x180000000)     # ImageBase (PE32+ is 8 bytes)
    struct.pack_into("<I", opt, 32, 0x1000)
    struct.pack_into("<I", opt, 36, 0x200)
    struct.pack_into("<H", opt, 40, 6); struct.pack_into("<H", opt, 48, 6)
    struct.pack_into("<I", opt, 56, 0x4000)
    struct.pack_into("<I", opt, 60, 0x400)
    struct.pack_into("<H", opt, 68, 2)
    struct.pack_into("<I", opt, 108, 16)             # NumberOfRvaAndSizes (PE32+ offset)

    def section(name, vs, va, rs, ra, ch):
        return name.ljust(8, b"\x00") + struct.pack("<IIII", vs, va, rs, ra) + \
               struct.pack("<IIHHI", 0, 0, 0, 0, ch)
    sections = section(b".text", 0x200, 0x1000, 0x200, 0x400, 0x60000020) + \
               section(b".rdata", 0x200, 0x2000, 0x200, 0x600, 0x40000040)
    headers = bytes(dos) + b"PE\x00\x00" + coff + bytes(opt) + sections
    headers += b"\x00" * (0x400 - len(headers))
    # Import-ish + export-ish strings so capability/keyword heuristics have something real
    body = (b"InternetOpenA\x00InternetConnectA\x00HttpSendRequestA\x00"
            b"CreateRemoteThread\x00VirtualAllocEx\x00WriteProcessMemory\x00"
            b"WS2_32.dll\x00WININET.dll\x00KERNEL32.dll\x00"
            b"ServiceMain\x00DllRegisterServer\x00")
    body += b"\x00" * (0x400 - len(body))
    return headers + body


def dll_attachment():
    return w("PrintConfig.dll", _valid_dll())


def exe_in_zip():
    """Plain .exe inside a zip -- the archive child re-triage must catch the PE."""
    p = os.path.join(OUT, "Invoice_Documents.zip")
    with zipfile.ZipFile(p, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("Invoice_78432.pdf", b"%PDF-1.4\n% decoy\n%%EOF\n")
        with open(DROPPER, "rb") as fh:
            zf.writestr("Invoice_78432.exe", fh.read())
    return p


def decoy_double_ext_in_zip():
    """PE named to look like a PDF via a padded double extension."""
    p = os.path.join(OUT, "Payment_Receipt.zip")
    with zipfile.ZipFile(p, "w", zipfile.ZIP_DEFLATED) as zf:
        with open(DROPPER, "rb") as fh:
            zf.writestr("Receipt.pdf" + " " * 40 + ".exe", fh.read())
    return p


def password_zip():
    """Password-protected archive hiding a PE -- gateway-evasion pattern. We cannot inspect
    the content (that is the point), but the sandbox must flag the encryption itself.
    Uses 7z via a helper container is overkill; zipfile can't AES, so use legacy ZipCrypto."""
    import subprocess
    p = os.path.join(OUT, "Secure_Invoice.zip")
    # Build with the `zip` tool inside a throwaway container for real ZipCrypto encryption.
    subprocess.run(
        ["docker", "run", "--rm", "-v", f"{OUT}:/s", "-w", "/s", "debian:bookworm-slim",
         "bash", "-c",
         "apt-get update -qq >/dev/null 2>&1 && apt-get install -y -qq zip >/dev/null 2>&1 && "
         "cp dropper.exe /tmp/invoice.exe && "
         "zip -q -j -P infected Secure_Invoice.zip /tmp/invoice.exe"],
        check=False, capture_output=True,
    )
    return p if os.path.exists(p) else None


def nested_zip():
    """zip -> zip -> .exe. Tests the one-level extraction limit honestly: the outer zip is
    unpacked, the inner zip is triaged as an archive child (not recursed into)."""
    inner = os.path.join(OUT, "_inner.zip")
    with zipfile.ZipFile(inner, "w", zipfile.ZIP_DEFLATED) as zf:
        with open(DROPPER, "rb") as fh:
            zf.writestr("payload.exe", fh.read())
    p = os.path.join(OUT, "Shipping_Label.zip")
    with zipfile.ZipFile(p, "w", zipfile.ZIP_DEFLATED) as zf:
        with open(inner, "rb") as fh:
            zf.writestr("label.zip", fh.read())
    os.remove(inner)
    return p


def pe_in_ole_document():
    """A legacy OLE2 document with a PE embedded as an OLE Package object -- the classic
    'double-click the embedded icon' smuggling trick. Built as a minimal OLE with an
    \x01Ole10Native-style stream holding the PE bytes."""
    with open(DROPPER, "rb") as fh:
        pe = fh.read()
    # Minimal single-storage OLE (reuse the CFBF layout from make_samples), stream = the PE.
    sector = 512
    payload = pe
    header = bytearray(sector)
    header[0:8] = b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"
    header[26:28] = struct.pack("<H", 3); header[28:30] = struct.pack("<H", 0xFFFE)
    header[30:32] = struct.pack("<H", 9); header[32:34] = struct.pack("<H", 6)
    header[44:48] = struct.pack("<I", 1); header[48:52] = struct.pack("<I", 1)
    header[56:60] = struct.pack("<I", 4096); header[60:64] = struct.pack("<I", 0xFFFFFFFE)
    header[68:72] = struct.pack("<I", 0xFFFFFFFE); header[76:80] = struct.pack("<I", 0)
    payload_sectors = (len(payload) + sector - 1) // sector
    fat = bytearray()
    fat += struct.pack("<I", 0xFFFFFFFD); fat += struct.pack("<I", 0xFFFFFFFE)
    for i in range(payload_sectors):
        fat += struct.pack("<I", 0xFFFFFFFE if i == payload_sectors - 1 else 2 + i + 1)
    fat += b"\xff" * (sector - len(fat))

    def de(name, etype, start, size, child=0xFFFFFFFF):
        e = bytearray(128); enc = name.encode("utf-16-le") + b"\x00\x00"
        e[0:len(enc)] = enc; e[64:66] = struct.pack("<H", len(enc)); e[66] = etype; e[67] = 1
        e[68:72] = struct.pack("<I", 0xFFFFFFFF); e[72:76] = struct.pack("<I", 0xFFFFFFFF)
        e[76:80] = struct.pack("<I", child)
        e[116:120] = struct.pack("<I", start); e[120:124] = struct.pack("<I", size)
        return bytes(e)
    directory = (de("Root Entry", 5, 0xFFFFFFFE, 0, child=1)
                 + de("\x01Ole10Native", 2, 2, len(payload))
                 + b"\x00" * 128 + b"\x00" * 128)
    directory += b"\x00" * ((sector - len(directory) % sector) % sector)
    blob = bytes(header) + bytes(fat) + directory + payload
    blob += b"\x00" * ((-len(blob)) % sector)
    return w("Quotation.doc", blob)


def obfuscated_pe():
    """A packed/obfuscated PE stub: single tiny import table (resolved at runtime), a
    high-entropy packed section, and an encrypted-looking overlay."""
    import random
    random.seed(7)
    dos = bytearray(0x80); dos[0:2] = b"MZ"; dos[0x3C:0x40] = struct.pack("<I", 0x80)
    coff = struct.pack("<HHIIIHH", 0x14C, 1, 0x5E000000, 0, 0, 0xE0, 0x0102)
    opt = bytearray(0xE0)
    struct.pack_into("<H", opt, 0, 0x10B); struct.pack_into("<I", opt, 16, 0x1000)
    struct.pack_into("<I", opt, 28, 0x400000); struct.pack_into("<I", opt, 32, 0x1000)
    struct.pack_into("<I", opt, 36, 0x200); struct.pack_into("<H", opt, 40, 6)
    struct.pack_into("<H", opt, 48, 6); struct.pack_into("<I", opt, 56, 0x3000)
    struct.pack_into("<I", opt, 60, 0x400); struct.pack_into("<H", opt, 68, 2)
    struct.pack_into("<I", opt, 92, 16)

    def section(name, vs, va, rs, ra, ch):
        return name.ljust(8, b"\x00") + struct.pack("<IIII", vs, va, rs, ra) + \
               struct.pack("<IIHHI", 0, 0, 0, 0, ch)
    # .text is W+X and virtually oversized (unpacks at runtime)
    sections = section(b".text", 0x8000, 0x1000, 0x200, 0x400, 0xE0000020)
    headers = bytes(dos) + b"PE\x00\x00" + coff + bytes(opt) + sections
    headers += b"\x00" * (0x400 - len(headers))
    packed = bytes(random.getrandbits(8) for _ in range(0x200))       # high entropy
    overlay = bytes(random.getrandbits(8) for _ in range(0x8000))     # encrypted-looking
    return w("Statement_2024.exe", headers + packed + overlay)


BUILDERS = [
    ("raw DLL attachment (PE32+ .dll, export dir, net/injection imports)", dll_attachment),
    ("obfuscated/packed PE (.exe, W+X oversized section, hi-entropy overlay)", obfuscated_pe),
    (".exe inside a zip (child re-triage)", exe_in_zip),
    ("decoy double-extension .exe in a zip (Receipt.pdf....exe)", decoy_double_ext_in_zip),
    ("password-protected zip hiding a PE (gateway evasion)", password_zip),
    ("nested zip -> zip -> .exe (one-level extraction limit)", nested_zip),
    ("PE embedded as an OLE object inside a .doc", pe_in_ole_document),
]


def main():
    if not os.path.exists(DROPPER):
        print("ERROR: tests/samples/dropper.exe missing (cross-compile it first)")
        return 1
    for desc, fn in BUILDERS:
        try:
            p = fn()
            if p:
                print(f"  {os.path.basename(p):<42} {os.path.getsize(p):>9} B  {desc}")
            else:
                print(f"  (skipped) {desc}")
        except Exception as e:
            print(f"  FAILED {fn.__name__}: {type(e).__name__}: {e}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
