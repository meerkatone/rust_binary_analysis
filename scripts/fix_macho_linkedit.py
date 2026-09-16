#!/usr/bin/env python3
"""Repair an ld-produced Mach-O whose LINKEDIT string pool is not 8-byte aligned."""

from __future__ import annotations

import argparse
import struct
import subprocess
from pathlib import Path


LC_SEGMENT_64 = 0x19
LC_SYMTAB = 0x2
MH_MAGIC_64 = 0xFEEDFACF


def repair(path: Path) -> bool:
    data = bytearray(path.read_bytes())
    if len(data) < 32 or struct.unpack_from("<I", data)[0] != MH_MAGIC_64:
        raise ValueError(f"{path}: expected a little-endian 64-bit Mach-O")

    ncmds = struct.unpack_from("<I", data, 16)[0]
    offset = 32
    symtab_command = None
    linkedit_command = None

    for _ in range(ncmds):
        command, command_size = struct.unpack_from("<II", data, offset)
        if command_size < 8 or offset + command_size > len(data):
            raise ValueError(f"{path}: invalid Mach-O load command")
        if command == LC_SYMTAB:
            symtab_command = offset
        elif command == LC_SEGMENT_64:
            segment_name = bytes(data[offset + 8 : offset + 24]).rstrip(b"\0")
            if segment_name == b"__LINKEDIT":
                linkedit_command = offset
        offset += command_size

    if symtab_command is None or linkedit_command is None:
        raise ValueError(f"{path}: missing LC_SYMTAB or __LINKEDIT")

    string_offset = struct.unpack_from("<I", data, symtab_command + 16)[0]
    padding = (-string_offset) % 8
    if padding == 0:
        return False

    # Removing the signature also removes LC_CODE_SIGNATURE and truncates its
    # blob, making the string table the final LINKEDIT payload to adjust.
    subprocess.run(
        ["codesign", "--remove-signature", str(path)],
        check=True,
        stdout=subprocess.DEVNULL,
    )
    data = bytearray(path.read_bytes())

    struct.pack_into("<I", data, symtab_command + 16, string_offset + padding)
    linkedit_size = struct.unpack_from("<Q", data, linkedit_command + 48)[0]
    struct.pack_into("<Q", data, linkedit_command + 48, linkedit_size + padding)
    data[string_offset:string_offset] = bytes(padding)
    path.write_bytes(data)

    subprocess.run(
        ["codesign", "--force", "--sign", "-", str(path)],
        check=True,
        stdout=subprocess.DEVNULL,
    )
    return True


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("dylib", type=Path)
    args = parser.parse_args()
    changed = repair(args.dylib)
    print(f"{'repaired' if changed else 'already aligned'}: {args.dylib}")


if __name__ == "__main__":
    main()
