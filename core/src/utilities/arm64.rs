/*
    SPDX-License-Identifier: AGPL-3.0-or-later
    SPDX-FileCopyrightText: 2025 Shomy
*/

use crate::error::{Error, Result};

pub fn force_return(data: &mut [u8], off: usize, value: u32) -> Result<()> {
    // ARM64: mov x0, #imm
    // Encoding: 0xd2800000 | (imm << 5)
    let mov_x0 = 0xD2800000u32 | ((value & 0xFFFF) << 5);
    let ret = 0xD65F03C0u32;

    data[off..off + 4].copy_from_slice(&mov_x0.to_le_bytes());
    data[off + 4..off + 8].copy_from_slice(&ret.to_le_bytes());

    Ok(())
}

pub fn encode_bl(src: u32, dst: u32) -> Result<u32> {
    let off = dst as i64 - src as i64;

    if !(-(1 << 27)..=((1 << 27) - 4)).contains(&off) {
        return Err(Error::penumbra("BL target out of range"));
    }

    let imm26 = (off >> 2) as u32 & 0x03FF_FFFF;
    let instr = 0x9400_0000u32 | imm26;

    Ok(instr)
}
