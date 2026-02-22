#!/usr/bin/env python3
#
# SPDX-FileCopyrightText: 2025 Shomy
# SPDX-License-Identifier: AGPL-3.0-or-later
#
import struct

from parse_da import DA, DAEntryRegion, DAFile, DAType

if __name__ == "__main__":
    import sys

    if len(sys.argv) < 5:
        print(f"Usage: {sys.argv[0]} <donor_da> <da1.bin> <da2.bin> <output_da>")
        sys.exit(1)

    if len(sys.argv) not in [5, 6, 7]:
        print(
            f"Usage: {sys.argv[0]} <donor_da> <da1.bin> <da2.bin> [<da1.sig>] [<da2.sig>] <output_da>"
        )
        sys.exit(1)

    donor_da_path = sys.argv[1]
    output_da_path = sys.argv[-1]
    args = sys.argv[2:-1]

    da1_path = args[0]
    da2_path = args[1]

    da1_sig = None
    da2_sig = None

    if len(args) >= 3:
        da1_sig_path = args[2]
        with open(da1_sig_path, "rb") as f:
            da1_sig = f.read()
        print(f"Using DA1 signature from: {da1_sig_path}")

    if len(args) == 4:
        da2_sig_path = args[3]
        with open(da2_sig_path, "rb") as f:
            da2_sig = f.read()
        print(f"Using DA2 signature from: {da2_sig_path}")

    with open(donor_da_path, "rb") as f:
        donor_da_raw = f.read()

    donor_da_file = DAFile.parse_da(donor_da_raw)

    with open(da1_path, "rb") as f:
        da1_raw = f.read()

    with open(da2_path, "rb") as f:
        da2_raw = f.read()

    da = donor_da_file.das[0]

    da1_len = len(da1_raw)
    da2_len = len(da2_raw)

    original_da1 = da.get_da1()
    original_da2 = da.get_da2()

    original_da1.data = da1_raw + (da1_sig or b"\x00" * original_da1.sig_len)
    original_da2.data = da2_raw + (da2_sig or b"\x00" * original_da2.sig_len)

    if da1_sig is not None:
        original_da1.sig_len = len(da1_sig)
    if da2_sig is not None:
        original_da2.sig_len = len(da2_sig)

    original_da1.length = da1_len + original_da1.sig_len
    original_da2.length = da2_len + original_da2.sig_len

    original_da1.region_length = da1_len
    original_da2.region_length = da2_len

    header_end = min(r.offset for r in da.regions)
    current_offset = header_end

    for region in da.regions:
        region.offset = current_offset
        region.length = len(region.data)
        current_offset += region.length

    patched_header = bytearray(donor_da_raw[:header_end])

    da_entry_start = 0x6C
    region_count = len(da.regions)

    for region_idx in range(region_count):
        region = da.regions[region_idx]
        region_entry_offset = da_entry_start + 0x14 + region_idx * 20

        struct.pack_into(
            "<IIIII",
            patched_header,
            region_entry_offset,
            region.offset,
            region.length,
            region.addr,
            region.region_length,
            region.sig_len,
        )

    with open(output_da_path, "wb") as out:
        out.write(bytes(patched_header))

        for region in da.regions:
            out.seek(region.offset)
            out.write(region.data)

    print(f"Updated DA file written to: {output_da_path}")
    print("Updated region offsets:")
    for i, region in enumerate(da.regions):
        print(
            f"  Region {i}: offset=0x{region.offset:08X}, length=0x{region.length:08X}, "
            f"region_length=0x{region.region_length:08X}, sig_len=0x{region.sig_len:08X}"
        )
