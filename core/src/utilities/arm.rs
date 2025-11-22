/*
    SPDX-License-Identifier: AGPL-3.0-or-later
    SPDX-FileCopyrightText: 2025 Shomy
*/

use crate::error::{Error, Result};

#[macro_export]
macro_rules! extract_ptr {
    (u32, $data:expr, $offset:expr) => {{
        if $offset + 4 <= $data.len() {
            u32::from_le_bytes([
                $data[$offset],
                $data[$offset + 1],
                $data[$offset + 2],
                $data[$offset + 3],
            ])
        } else {
            0
        }
    }};

    (u64, $data:expr, $offset:expr) => {{
        if $offset + 8 <= $data.len() {
            u64::from_le_bytes([
                $data[$offset],
                $data[$offset + 1],
                $data[$offset + 2],
                $data[$offset + 3],
                $data[$offset + 4],
                $data[$offset + 5],
                $data[$offset + 6],
                $data[$offset + 7],
            ])
        } else {
            0
        }
    }};
}

pub fn to_thumb_addr(pos: usize, base_addr: u32) -> u32 {
    ((pos as u32) + base_addr) | 1
}

pub fn encode_bl(src: u32, dst: u32) -> Vec<u8> {
    let off = dst as i32 - (src as i32 + 4);
    let hi = ((off >> 12) & 0x7FF) as u16;
    let lo = ((off >> 1) & 0x7FF) as u16;

    let hi_bytes = (0xF000 | hi).to_le_bytes();
    let lo_bytes = (0xF800 | lo).to_le_bytes();

    vec![hi_bytes[0], hi_bytes[1], lo_bytes[0], lo_bytes[1]]
}

pub fn encode_ldr(
    dest_reg: u16,
    instr_offset: usize,
    dat_offset: usize,
    base_addr: u32,
) -> Result<[u8; 2]> {
    if dest_reg > 7 {
        return Err(Error::penumbra("Destination register must be in 0..7"));
    }

    // In arm, PC is 4 bytes ahead, !0x3 is for alignment
    let pc = ((base_addr + instr_offset as u32) + 4) & !0x3;
    let dat_off = base_addr + dat_offset as u32;

    let delta = (dat_off - pc) as usize;
    if delta.is_multiple_of(4) {
        return Err(Error::penumbra("Delta for encoding LDR is not aligned!"));
    }

    // Offset in words of the data from PC
    let imm8 = delta / 4;

    // A minimal ldr instruction is 0x4800
    let instruction = 0x4800u16 | dest_reg << 8 | imm8 as u16;
    Ok(instruction.to_le_bytes())
}
