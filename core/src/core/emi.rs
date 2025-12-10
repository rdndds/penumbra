/*
    SPDX-License-Identifier: AGPL-3.0-or-later
    SPDX-FileCopyrightText: 2025 Shomy
*/
use log::error;

use crate::utilities::patching::{HEX_NOT_FOUND, find_pattern};

const FILE_INFO_EMI: &str = "4D4D4D0138000000";

pub fn extract_emi_settings(preloader: &[u8]) -> Option<Vec<u8>> {
    let header_off = find_pattern(preloader, FILE_INFO_EMI, 0);
    if header_off == HEX_NOT_FOUND {
        error!("Failed to extract EMI: EMI header not found.");
        return None;
    }

    let mut data = &preloader[header_off..];

    let mlen = u32::from_le_bytes(data[0x20..0x24].try_into().ok()?) as usize;
    let siglen = u32::from_le_bytes(data[0x2C..0x30].try_into().ok()?) as usize;
    data = &data[..mlen - siglen];

    let mut dramsize = u32::from_le_bytes(data[data.len() - 4..].try_into().ok()?) as usize;
    if dramsize == 0 && data.len() >= 0x804 {
        data = &data[..data.len() - 0x800];
        dramsize = u32::from_le_bytes(data[data.len() - 4..].try_into().ok()?) as usize;
    }
    data = &data[data.len() - dramsize - 4..data.len() - 4];

    Some(data[..].to_vec())
}
