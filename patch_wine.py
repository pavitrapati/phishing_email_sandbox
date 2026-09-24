#!/usr/bin/env python3
import sys
import os

REPLACEMENTS = {
    b"wine_get_unix_file_name": b"fake_get_unix_file_name",
    b"Software\\Wine": b"Software\\Winf",
    b"SOFTWARE\\Wine": b"SOFTWARE\\Winf",
    b"S\x00o\x00f\x00t\x00w\x00a\x00r\x00e\x00\\\x00W\x00i\x00n\x00e\x00": b"S\x00o\x00f\x00t\x00w\x00a\x00r\x00e\x00\\\x00W\x00i\x00n\x00f\x00",
    b"S\x00O\x00F\x00T\x00W\x00A\x00R\x00E\x00\\\x00W\x00i\x00n\x00e\x00": b"S\x00O\x00F\x00T\x00W\x00A\x00R\x00E\x00\\\x00W\x00i\x00n\x00f\x00",
}

def patch_file(path):
    try:
        with open(path, "rb") as f:
            data = f.read()
    except Exception:
        return

    patched = False
    for target, replacement in REPLACEMENTS.items():
        if target in data:
            data = data.replace(target, replacement)
            patched = True

    if patched:
        try:
            with open(path, "wb") as f:
                f.write(data)
            print(f"Patched {path}")
        except Exception as e:
            print(f"Failed to write {path}: {e}")

if __name__ == "__main__":
    for root_dir in sys.argv[1:]:
        if os.path.isdir(root_dir):
            for root, _, files in os.walk(root_dir):
                for file in files:
                    if file.endswith((".dll", ".so", ".drv", ".exe", ".ds")):
                        patch_file(os.path.join(root, file))
        else:
            patch_file(root_dir)
