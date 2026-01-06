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

pub fn encode_bl_arm(src: u32, dst: u32) -> Result<u32> {
    let off = dst as i64 - (src as i64 + 8);

    if !(-(1 << 25)..=((1 << 25) - 4)).contains(&off) {
        return Err(Error::penumbra("BL target out of range"));
    }

    let imm24 = (off >> 2) as u32 & 0x00FF_FFFF;
    let instr = 0xEB00_0000u32 | imm24;

    Ok(instr)
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
    if !delta.is_multiple_of(4) {
        return Err(Error::penumbra("Delta for encoding LDR is not aligned!"));
    }

    // Offset in words of the data from PC
    let imm8 = delta / 4;

    // A minimal ldr instruction is 0x4800
    let instruction = 0x4800u16 | dest_reg << 8 | imm8 as u16;
    Ok(instruction.to_le_bytes())
}

pub fn force_return(data: &mut [u8], off: usize, value: u32, thumb_mode: bool) -> Result<()> {
    if thumb_mode {
        let mov_r0 = 0x2000u16 | ((value & 0xFF) as u16);
        let bx_lr = 0x4770u16;

        data[off..off + 2].copy_from_slice(&mov_r0.to_le_bytes());
        data[off + 2..off + 4].copy_from_slice(&bx_lr.to_le_bytes());
        return Ok(());
    }

    let mov_r0 = 0xE3A00000u32 | (value & 0xFF) | ((value << 4) & 0xF00);
    let bx_lr = 0xE12FFF1Eu32;

    data[off..off + 4].copy_from_slice(&mov_r0.to_le_bytes());
    data[off + 4..off + 8].copy_from_slice(&bx_lr.to_le_bytes());

    Ok(())
}
