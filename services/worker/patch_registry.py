#!/usr/bin/env python3
"""Patch Wine's system.reg to register AppInit_DLLs.

Wine's system.reg is a structured text file where:
  - Each section header is [KeyPath] <timestamp>
  - Keys must appear in sorted order within their top-level namespace
  - Values follow their section header, one per line

This script finds or creates the
  [Software\\\\Microsoft\\\\Windows NT\\\\CurrentVersion\\\\Windows]
section and adds AppInit_DLLs values to it.
"""
import os
import re
import sys
import time


def main():
    wineprefix = os.environ.get("WINEPREFIX", os.path.expanduser("~/.wine"))
    reg_path = os.path.join(wineprefix, "system.reg")
    # Accept a path already in Wine's system.reg format (C:\\fix_ntquery.dll)
    # The Dockerfile passes it in single-quoted form which preserves backslashes.
    dll_path = sys.argv[1] if len(sys.argv) > 1 else "C:\\\\fix_ntquery.dll"

    with open(reg_path, "r", encoding="utf-8") as f:
        content = f.read()

    lines = content.splitlines(keepends=True)

    # The target section key (with Wine's double-backslash encoding)
    target_key = "[Software\\\\Microsoft\\\\Windows NT\\\\CurrentVersion\\\\Windows]"

    # Wine timestamps: seconds since 1601-01-01 as a decimal integer
    timestamp = "1789457453"

    # Values to inject
    values = [
        f'"AppInit_DLLs"="{dll_path}"',
        '"LoadAppInit_DLLs"=dword:00000001',
    ]

    # Search for existing section
    section_idx = None
    for i, line in enumerate(lines):
        stripped = line.strip()
        if stripped.startswith(target_key):
            section_idx = i
            break

    if section_idx is not None:
        # Section already exists. Find where it ends (next section or EOF)
        # and insert values that don't already exist.
        insert_at = section_idx + 1
        # Skip past any existing values in this section
        while insert_at < len(lines):
            l = lines[insert_at].strip()
            if l.startswith("[") or l == "":
                break
            insert_at += 1

        # Insert our values before the next section/blank line
        for val in reversed(values):
            # Check if value already present in section
            val_name = val.split("=")[0]
            already_present = False
            for j in range(section_idx + 1, insert_at):
                if lines[j].strip().startswith(val_name):
                    already_present = True
                    break
            if not already_present:
                lines.insert(insert_at, val + "\n")
    else:
        # Section doesn't exist. Find the right sorted position.
        # Wine's system.reg has keys sorted: Software\\... comes before System\\...
        # Find the last [Software\\...] section
        last_software_line = None
        for i, line in enumerate(lines):
            stripped = line.strip()
            if stripped.startswith("[Software\\\\"):
                last_software_line = i

        if last_software_line is not None:
            # Find the end of that section (next section or EOF)
            insert_at = last_software_line + 1
            while insert_at < len(lines):
                l = lines[insert_at].strip()
                if l.startswith("["):
                    break
                insert_at += 1

            # Insert our new section before the next [System\\...] or other key
            new_section = [
                "\n",
                f"{target_key} {timestamp}\n",
                f"#time=1dd44e423d46734\n",
            ]
            for val in values:
                new_section.append(val + "\n")
            new_section.append("\n")

            for j, line in enumerate(new_section):
                lines.insert(insert_at + j, line)
        else:
            # Fallback: append at end (shouldn't happen with a valid prefix)
            lines.append("\n")
            lines.append(f"{target_key} {timestamp}\n")
            lines.append(f"#time=1dd44e423d46734\n")
            for val in values:
                lines.append(val + "\n")
            lines.append("\n")

    with open(reg_path, "w", encoding="utf-8") as f:
        f.writelines(lines)

    print(f"[patch_registry] Patched {reg_path} with AppInit_DLLs={dll_path}")


if __name__ == "__main__":
    main()
